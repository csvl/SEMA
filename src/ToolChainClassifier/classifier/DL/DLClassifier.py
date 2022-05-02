import copy
try:
    import torch
    import torch.nn as nn
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
except:
    print("Deep learning model do no support pypy3")
    exit(-1)
import numpy as np

try:
    from clogging.CustomFormatter import CustomFormatter
    from classifier.Classifier import Classifier
except:
    from ...clogging.CustomFormatter import CustomFormatter
    from ..Classifier import Classifier
       

RANDOM_SEED=np.random.seed(10)

class Encoder(nn.Module):
    def __init__(self,  n_features, embedding_dim=64):
        super(Encoder, self).__init__()
        self.n_features =  n_features
        self.embedding_dim, self.hidden_dim = embedding_dim, 2 * embedding_dim
        self.rnn1 = nn.LSTM(
            input_size=n_features,
            hidden_size=self.hidden_dim,
            num_layers=1,
            batch_first=True
        )
        self.rnn2 = nn.LSTM(
            input_size=self.hidden_dim,
            hidden_size=embedding_dim,
            num_layers=1,
            batch_first=True
        )

    def forward(self, x):
        x, (hidden_n, cell_n) = self.rnn1(x)
        x, (hidden_n, cell_n) = self.rnn2(x)
        return hidden_n.reshape((x.shape[0], self.embedding_dim))
    

class Decoder(nn.Module):
    def __init__(self,  input_dim=64, n_features=1): # TODO custom parameter
        super(Decoder, self).__init__()
        self.input_dim =  input_dim
        self.hidden_dim, self.n_features = 2 * input_dim, n_features
        self.rnn1 = nn.LSTM(
            input_size=input_dim,
            hidden_size=self.hidden_dim,
            num_layers=1,
            batch_first=True
        )
        self.rnn2 = nn.LSTM(
            input_size=self.hidden_dim,
            hidden_size=n_features,
            num_layers=1,
            batch_first=True
        )
        
        self.dense = nn.Linear(n_features,n_features)

    def forward(self, x,seq_len):
        x = x.repeat(x.shape[0],seq_len, 1)
        x = x.reshape((x.shape[0], seq_len, self.input_dim))
        x, (hidden_n, cell_n) = self.rnn1(x)
        x, (hidden_n, cell_n) = self.rnn2(x)
        x = x.reshape((x.shape[0],seq_len, self.n_features))
        x = self.dense(x)
        return x

class RecurrentAutoencoder(nn.Module):
    def __init__(self, n_features, embedding_dim=64):
        super(RecurrentAutoencoder, self).__init__()
        self.encoder = Encoder(n_features, embedding_dim)
        self.decoder = Decoder(embedding_dim, n_features)

    def forward(self, x):
        x1 = self.encoder(x)
        x2 = self.decoder(x1, x.shape[1])
        return x1,x2

    def encode(self,x):
        with torch.no_grad():
            return self.encoder(x)

    def decode(self,x, seq_len):
        with torch.no_grad():
            return self.decoder(x,seq_len)

class mClassifier(nn.Module):
    def __init__(self, n_features):
        super(mClassifier, self).__init__()
        self.n_features = n_features
        n_hidden = 2*n_features
        self.Linear1 = nn.Linear(n_features, n_hidden)
        self.Linear2 = nn.Linear(n_hidden, 1)

    def forward(self, x):
        y1 = self.Linear1(x)
        y2 = self.Linear2(y1)
        return y2

    def predict(self, x):
        with torch.no_grad():
            y1 = self.Linear1(x)
            y2 = self.Linear2(y1)
            return y2

class DLClassifier(nn.Module):
    def __init__(self, n_features,embedding_dim, classes):
        super(DLClassifier, self).__init__()
        self.n_features = n_features
        self.embedding_dim = embedding_dim
        self.classes = classes # store family name
        n_classes = len(classes)
        self.n_classes = n_classes
        n_hidden = 2*n_features # TODO
        self.RNN = RecurrentAutoencoder(n_features, embedding_dim).to(device)        
        self.mCNN = nn.ModuleList([mClassifier(embedding_dim) for i in range(n_classes)]).to(device)
        self.L = nn.Softmax(dim=1).to(device)

    def forward(self, x):
        x2,y = self._evaluate(x)
        return x2, y

    def predict(self, x):
        with torch.no_grad():
            _,y = self._evaluate(x)
            return y
            
    def _evaluate(self, x):
        x1, x2 = self.RNN(x)
        out = [self.mCNN[i](x1) for i in range(self.n_classes)]
        y = torch.cat(out,1)
        return x2,self.L(y)

    def update(self, classes):
        class_idx = list()
        for i in range(len(classes)):
            if classes[i] in self.classes:
                class_idx.append(self.classes.index(classes[i]))
            else:
                class_idx.append(len(self.classes))
                self.classes.append(classes[i])
                self.mCNN.append(mClassifier(self.embedding_dim))
        self.n_classes = len(self.classes)
        return class_idx

    def get_class_id(self, label):
        if label in self.classes:
            return self.classes.index(label)
        else:
            return -1

