import copy
import os
try:
	import torch
	import torch.nn as nn
	from torch.nn import functional as F
	from torch.utils.data import DataLoader, random_split
except:
	print("Deep learning model do no support pypy3")
	exit(-1)
import progressbar
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, f1_score, balanced_accuracy_score, accuracy_score
import numpy as np
import logging

RANDOM_SEED=np.random.seed(10)

try:
	from .DLClassifier import DLClassifier	
	from .DLDataset import DLDataset
	from ..Classifier import Classifier
	from clogging.CustomFormatter import CustomFormatter
except:
	from .DLClassifier import DLClassifier	
	from .DLDataset import DLDataset
	from ..Classifier import Classifier
	from clogging.CustomFormatter import CustomFormatter
	 

class DLTrainerClassifier(Classifier):
	def __init__(self, path, threshold=0.45, 
				shared_type=0):

		super().__init__(path,'DLTrainerClassifier', threshold)
		ch = logging.StreamHandler()
		ch.setLevel(logging.INFO)
		ch.setFormatter(CustomFormatter())
		self.log = logging.getLogger("DLTrainerClassifier")
		self.log.setLevel(logging.INFO)
		self.log.addHandler(ch)
		self.log.propagate = False

		self.vector_size = 4
		self.data_train = None
		self.data_scale = 0.9
		self.train_dataset = None
		self.val_dataset = None
		self.n_features = 0
		self.embedding_dim = 0
		self.classe = 0
		self.n_epochs = 5

		self.y_true = []
		self.y_pred = []
		self.labels = []
		self.TP = 0
		self.TPR = 0
		self.loss = 0

		self.test_loader = None
		self._model = None
		self.shared_type = shared_type
	
	def get_stat_classifier(self, save_path = None):
		self.TPR = self.TP/len(self.test_loader)
		self.loss = self.loss/len(self.test_loader)
		self.log.info(f"Labels: {len(self.labels)}\nDetect {self.TP}/{len(self.test_loader)}\nDetection rate: {self.TPR}\nLoss: {self.loss}")
		
		acc = accuracy_score(self.y_true, self.y_pred)
		bacc = balanced_accuracy_score(self.y_true, self.y_pred)
		fscore = f1_score(self.y_true,self.y_pred, average='weighted')
		self.log.info(f"acc\t{acc}\nbacc\t{bacc}\nfscore\t{fscore}")
		cm = confusion_matrix(self.y_true, self.y_pred,labels = sorted(self.labels))
		disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=sorted(self.labels))
		disp.plot()
		#plt.show()
		if save_path is None:
			plt.show()
		else:
			plt.savefig(f"{save_path}_CM_fig.png", bbox_inches='tight')
		self.log.info(f"TPR\t{self.TPR}")
		self.log.info(f"Loss\t{self.loss}")

	def classify(self):
		self._model.eval()
		criterion_x = nn.MSELoss(reduction='sum')
		criterion_y = nn.BCELoss()
		
		self.labels =[c for c in self._model.classes]
		#self.log.info(sorted(range(len(labels)), key=labels.__getitem__))
		#self.log.info("gt_id\tgt_name\tpredict_id\tpredict_name\tpredict_value\tsize")
		self.loss = 0.
		for x,y in self.test_loader:
			y_predict = self._model.predict(x[0])
			l = self.loss_calc(x,y_predict, x,y[0],criterion_x,criterion_y)
			if l is not None:
				self.loss+=l.item()
			
			i = torch.argmax(y_predict).item()
			j = torch.argmax(y).item()
			if i== j:
				self.TP +=1
			self.y_true.append(self.labels[j])
			self.y_pred.append(self.labels[i])
		

	def detection(self):
		"""
		Malware vs cleanware
		"""
		pass
	
	def train(self, input_path, sepoch=1):
		# TODO
		apiname = "APInameseq.txt"
		fname = "mapping.txt"
		apipath = apiname #os.path.join(dir_path, apiname)
		mappath = fname #os.path.join(dir_path, fname)
		self.data_train = DLDataset(input_path, mappath, apipath,self.vector_size)
		d_train, d_val = random_split(self.data_train, [int(len(self.data_train)*self.data_scale), len(self.data_train)-int(len(self.data_train)*self.data_scale)])
		self.train_dataset = DataLoader(d_train, batch_size=1,num_workers=0)
		self.val_dataset = DataLoader(d_val, batch_size=1,num_workers=0)
		self.n_features, self.embedding_dim, self.classe = self.vector_size*2, 64, self.data_train.classes

		
		self.test_loader = DataLoader(self.data_train, batch_size=1,num_workers=4)
		self._model = DLClassifier(self.n_features,self.embedding_dim, self.classe)

		loss_error =  False
		optimizer = torch.optim.Adam(self._model.parameters(), lr=1e-3)
		criterion_x = nn.MSELoss(reduction='mean')
		criterion_y = nn.BCELoss()
		# criterion_y = nn.CrossEntropyLoss()
		
		history = dict(train=[], val=[])
		best_model_wts = copy.deepcopy(self._model.state_dict())
		best_loss = 1e9
		self._model.train()
		for epoch in range(sepoch, self.n_epochs + 1):
			train_losses = []
			self.log.info(f"Epoch {epoch}/{self.n_epochs}:")
			bar = progressbar.ProgressBar(max_value=len(self.train_dataset)+len(self.val_dataset))
			bar.start()
			i_count = 0
			for seq_true,y_true in self.train_dataset:
				optimizer.zero_grad()
				x = seq_true[0] 
				y= y_true[0]
				x2,y_pred = self._model(x)
				loss = self.loss_calc(x2,y_pred, 
							x, y, 
							criterion_x,
							criterion_y)
				loss.backward()
				optimizer.step()
				train_losses.append(loss.item())
				i_count+=1
				bar.update(i_count)
			val_loss = None
			if len(self.val_dataset)>0:
				val_losses = []
				self._model.eval()
				with torch.no_grad():
					for seq_true,y in self.val_dataset:
						x = seq_true[0]
						x2,y_pred = self._model(x)
						loss = self.loss_calc(x2, y_pred, x, y[0], criterion_x, criterion_y)
						val_losses.append(loss.item())
						i_count+=1
						bar.update(i_count)
				val_loss = np.mean(val_losses)
				history['val'].append(val_loss)
				if val_loss < best_loss:
					best_loss = val_loss
					best_model_wts = copy.deepcopy(self._model.state_dict())
			bar.update(len(self.train_dataset)+len(self.val_dataset))
			bar.finish()
			if loss_error:
				self.log.info(f"\tEpoch {epoch}: loss error!")
				self._model.load_state_dict(best_model_wts)
				continue
			train_loss = np.mean(train_losses)
			if train_loss < best_loss:
					best_loss = train_loss
					best_model_wts = copy.deepcopy(self._model.state_dict())
			history['train'].append(train_loss)
			
			self.log.info(f'\tEpoch {epoch}: train loss {train_loss} val loss {val_loss}')
			
		self._model.load_state_dict(best_model_wts)
		self.log.info(f"\t\tLoss: {best_loss}")
		return self._model, history
		
	def loss_calc(self,x,y,x_target, y_target,criterion_x,criterion_y):
		f = torch.sigmoid
		try:
			loss_x = criterion_x(f(x),f(x_target))
			loss_y = criterion_y(y,y_target)
		except:
			self.log.info(f"y {y}")
			self.log.info(f"y target {y_target}")
			"""self.log.info(f"loss x {loss_x}")
			self.log.info(f"loss y {loss_y}")
			message = f"\nx={x}\nx_target={x_target}\ny={y}\ny_target={y_target}"
			logging.info(message)"""
			return None
		return loss_y+loss_x
	
	@property
	def classes(self):
		return self._model.classes
	
	@property
	def share_model(self):
		if self.shared_type==1:
			return self._model.RNN.encoder
		else:
			return self._model

	@share_model.setter
	def share_model(self, value):
		if self.shared_type==1:
			self._model.RNN.encoder = value
		else:
			self._model = value

	@property
	def modelparameters(self):
		with torch.no_grad():
			return self.share_model.parameters()

	@modelparameters.setter
	def modelparameters(self, values):
		with torch.no_grad():
			for i,p in enumerate(self.share_model.parameters()):
				v = torch.tensor(values[i]).reshape(p.size())
				p.copy_(v)
				
	def get_model_parameter(self):
		para =[]
		for i,p in enumerate(self.share_model.parameters()):
			v = p.flatten().tolist()
			para.append(v)
		return para

	@property
	def model(self):
		return self._model

	@model.setter
	def model(self, value):
		self._model = value
