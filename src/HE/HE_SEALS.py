import tenseal as ts
import torch
import base64

class F:
	@staticmethod
	def init_encrypt(poly_modulus_degree=8192,bits_scale=26):
		coeff_mod_bit_sizes=[31, bits_scale, bits_scale, bits_scale, bits_scale, bits_scale, bits_scale, 31]
		context = ts.context(
			ts.SCHEME_TYPE.CKKS,
			poly_modulus_degree,
			coeff_mod_bit_sizes
		)
		context.global_scale = 2**bits_scale
		context.generate_galois_keys()
		key = context.secret_key()
		context.make_context_public()
		return context, key
		
	
	@staticmethod
	def encrypt_weight(context, submodel):
		"""
		Convert model parameters to encrypted text by context
		"""
		ctx = ts.context_from(context)
		para = list()
		with torch.no_grad():
			for p in submodel.parameters():
				#print(p.size())
				v = p.flatten().tolist()
				#enc_v1 = ts.ckks_vector(ctx, v)
				#enc_para.append(enc_v1)
				para.extend(v)
		enc_para = list()
		chunk_offset = 4096
		chunk_start = 0
		chunk_end = chunk_offset
		#print(len(para))
		while chunk_end < len(para):
			#print(chunk_start, chunk_end, chunk_end-chunk_start)
			enc_v1 = ts.ckks_vector(ctx, para[chunk_start:chunk_end])
			txt = F.bytes_to_string(enc_v1.serialize())
			#enc_para.append(enc_v1)
			enc_para.append(txt)
			chunk_start = chunk_end
			chunk_end +=chunk_offset
		if chunk_end > len(para):
			chunk_end = len(para)
			enc_v1 = ts.ckks_vector(ctx, para[chunk_start:chunk_end])
			txt = F.bytes_to_string(enc_v1.serialize())
			#enc_para.append(enc_v1)
			enc_para.append(txt)
			#print(chunk_start, chunk_end, chunk_end-chunk_start)

		#print(len(enc_para))
		return enc_para

	@staticmethod
	def decrypt_para(key,context, enc_para):
		para = list()
		for p in enc_para:
			tenc = F.string_to_enc(p,context)
			para.append(tenc.decrypt(key))
		return para
	
	@staticmethod
	def encrypt_para(context, para):
		txt_para = list()
		for p in para:
			tenc = ts.ckks_vector(context, p)
			txt = F.bytes_to_string(tenc.serialize())
			txt_para.append(txt)
		return txt_para

	@staticmethod
	def update_encrypt(key,context,enc_para, num, submodel):
		ctx = context#ts.context_from(F.string_to_bytes(context))
		para = list()
		for p in enc_para:
			tenc = F.string_to_enc(p,ctx)
			para.extend(tenc.decrypt(key))
		para = torch.tensor(para)
		if num > 1:
			para = para/num
		
		chunk_start = -1
		chunk_end = 0
		with torch.no_grad():
			for p in submodel.parameters():
				#print(p.size(), p.numel())
				chunk_start = chunk_end
				chunk_end += p.numel()
				#print(chunk_start, chunk_end)
				#v = torch.tensor(para[chunk_start:chunk_end]).reshape(p.size())
				v = para[chunk_start:chunk_end].reshape(p.size())
				p.copy_(v)
		return submodel
	
	@staticmethod
	def context_from_string(ctx_str):
		tb = F.string_to_bytes(ctx_str)
		ctx = ts.context_from(tb)
		return ctx
		
	@staticmethod
	def string_to_enc(x, ctx):
		tb = F.string_to_bytes(x)
		tenc = ts.ckks_vector_from(ctx,tb)
		return tenc

	@staticmethod
	def enc_to_string(x):
		return F.bytes_to_string(x.serialize())

	@staticmethod
	def add_weight(enc_para,context):
		ctx = ts.context_from(F.string_to_bytes(context))
		enc = [F.string_to_enc(enc_para[0][k],ctx) for k in range(len(enc_para[0])) ]
		for i in range(1, len(enc_para)):
			for j in range(len(enc_para[i])):
				t_e = F.string_to_enc(enc_para[i][j],ctx)
				enc[j] += t_e
		ret = [F.enc_to_string(enc[k]) for k in range(len(enc)) ]
		return ret
		
	@staticmethod
	def bytes_to_string(x):
		"""
		@x: serialized data (bytes)
		@return: string
		"""
		s_x = base64.encodebytes(x).decode()
		return s_x
	
	@staticmethod
	def string_to_bytes(x):
		"""
		@x: string
		@return: serialized data (bytes)
		"""
		s_x = base64.decodebytes(x.encode())
		return s_x
		
		
	@staticmethod
	def para_decrypt(key,enc_para, num):
		para = list()
		for p in enc_para:
			para.extend(p.decrypt(key))
		#print(para)
		#print(len(para))
		para = torch.tensor(para)
		if num > 1:
			para = para/num
		return para

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class RSA:
	@staticmethod
	def generate_key():
		sk = rsa.generate_private_key(public_exponent = 65537,key_size=2048,)
		pk = sk.public_key()
		return sk, pk
	
	@staticmethod
	def serialize_pk(pk):
		pem = pk.public_bytes(encoding= serialization.Encoding.PEM,
			format= serialization.PublicFormat.SubjectPublicKeyInfo
			)
		return pem
	
	@staticmethod
	def bytes_to_pk(pem):
		return serialization.load_pem_public_key(pem)
	
	@staticmethod
	def encrypt(pk, msg):
		enc_para = list()
		chunk_offset = 128 
		chunk_start = 0
		chunk_end = chunk_offset
		#print(len(para))
		while chunk_end < len(msg.encode()):
			ciphertext = pk.encrypt(msg.encode()[chunk_start:chunk_end],
						padding.OAEP(mgf= padding.MGF1(algorithm=hashes.SHA256()), 
						algorithm= hashes.SHA256(),
						label= None
						)
					)
			txt = F.bytes_to_string(ciphertext)
			enc_para.append(txt)
			chunk_start = chunk_end
			chunk_end += chunk_offset
		if chunk_end > len(msg.encode()):
			chunk_end = len(msg.encode())
			ciphertext = pk.encrypt(msg.encode()[chunk_start:chunk_end],
						padding.OAEP(mgf= padding.MGF1(algorithm=hashes.SHA256()), 
						algorithm= hashes.SHA256(),
						label= None
						)
					)
			txt = F.bytes_to_string(ciphertext)
			enc_para.append(txt)
		return enc_para
		
	@staticmethod
	def decrypt(sk, ciphertext):
		plaintext = sk.decrypt(F.string_to_bytes(ciphertext),
			padding.OAEP(mgf= padding.MGF1(algorithm=hashes.SHA256()), 
					algorithm= hashes.SHA256(),
					label= None
					)
				)
		return plaintext.decode()
