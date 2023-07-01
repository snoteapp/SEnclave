import LZString from 'lz-string';
import OpenCrypto from 'opencrypto';

import Utils from './utils';

const cryptoLib = window.crypto || window.msCrypto;
const cryptoApi = cryptoLib.subtle || cryptoLib.webkitSubtle;

const SEnclave={};

const crypt=new OpenCrypto();

const _state={};
const _keystore={};
const _prvstore={};

function _resetObject(obj) {
	for (var p in obj) delete obj[p];
}

function _resetMemory() {
	_resetObject(_prvstore);
	_resetObject(_keystore);
	Object.assign(_prvstore, {
		version:1,
		user:false,
		state:'uninitialized',
		deviceId:Utils.unique(30),
		sessionId:Utils.unique(30)
	});
}
_resetMemory();

// export getters
['user','state','deviceId','sessionId','version'].forEach(function(prop) {
	Object.defineProperty(SEnclave, prop, { 
		get: function() { return _prvstore[prop]; } 
	});
});

['tkn'].forEach(function(prop) {
	Object.defineProperty(SEnclave, prop, { 
		get: function() { return _keystore[prop]; } 
	});
});


function _setState(state) {
	if (state==_prvstore.state) return;
	_prvstore.state=state;
	console.info('SEnclave.state', state);
}


function _generateRecoveryKey() {
	var parts=[];
	for(var i=0;i<3;i++) {
		parts.push(Utils.unique(6,32));
	}
	return parts.join('-');
}

async function _passwordHash(email, password) {
	var salt=crypt.stringToArrayBuffer(email);
	var passwordHash=await crypt.hashPassphrase(password, salt, 800102, { hash: 'SHA-512', length: 256, cipher: 'AES-GCM', usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true });
	// convert hex to base64
	passwordHash=crypt.arrayBufferToBase64(crypt.hexStringToArrayBuffer(passwordHash));
	return passwordHash;
}

function _removePemHeaders(pem) {
	return pem.replace(/^--.*--$/gm,'').replace(/[\r\n]/g,''); // remove lines and --- headers
}

// create new keys
async function _createAccountKeys(email, password) {
	var iKeyPair=await crypt.getRSAKeyPair(2048, "SHA-512", "RSA-OAEP", ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], true);

	var ePrvKey=await crypt.encryptPrivateKey(iKeyPair.privateKey, password, 800100, "SHA-512", "AES-GCM", 256);
	ePrvKey=_removePemHeaders(ePrvKey);
	var ePubKey=await crypt.cryptoPublicToPem(iKeyPair.publicKey);
	ePubKey=_removePemHeaders(ePubKey);
	var hPwd=await _passwordHash(email, password);

	// recovery
	var cRecKey=_generateRecoveryKey();
	var sRecKey=_generateRecoveryKey();

	var iPemPrvKey=await crypt.cryptoPrivateToPem(iKeyPair.privateKey);
	iPemPrvKey=_removePemHeaders(iPemPrvKey);
	var iRec=JSON.stringify({ts:Date.now(), hPwd:hPwd, iPrvKey:iPemPrvKey});

	var rPass=[cRecKey, sRecKey].join('-');
	var salt=crypt.stringToArrayBuffer(email);
	var iKey=await crypt.derivePassphraseKey(rPass, salt, 800100, { hash: 'SHA-512', length: 256, cipher: 'AES-GCM', usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: false });
	var eRec=await crypt.encrypt(iKey, crypt.stringToArrayBuffer(iRec));

	// shared key
	var iShrKey=await crypt.getSharedKey(256, {cipher: 'AES-GCM', usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true });
	var eShrKey=await crypt.encryptKey(iKeyPair.publicKey, iShrKey);

	var keys={
		hPwd:hPwd,
		ePubKey:ePubKey,
		ePrvKey:ePrvKey,
		cRecKey:cRecKey,
		sRecKey:sRecKey,
		eShrKey:eShrKey,
		iShrKey:iShrKey,
		eRec:eRec
	}

	return keys;
}



async function _decryptUserKeys(user, password) {
	if (!user || !user.ekeys) return false;
	try {
		var ekeys=user.ekeys;
		var keys={};
		keys.iPrvKey=await crypt.decryptPrivateKey(ekeys.ePrvKey, password, { name: 'RSA-OAEP', hash: 'SHA-512', usages: ['decrypt', 'unwrapKey'], isExtractable: false});
		keys.iPubKey=await crypt.pemPublicToCrypto(ekeys.ePubKey, { name: 'RSA-OAEP', hash: 'SHA-512', usages: ['encrypt', 'wrapKey'], isExtractable: false});
		keys.iShrKey=await crypt.decryptKey(keys.iPrvKey, ekeys.eShrKey, { type: 'raw', name: 'AES-GCM', length: 256, usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: false});

		return keys;
	} catch(ex) {
		console.error(ex);
	}	
	return false;
}

SEnclave.signup=async function(email, password, code) {
	var ekeys=await _createAccountKeys(email, password);

	var user={
		email:email
	};
	user.ekeys={
		ePrvKey:ekeys.ePrvKey, ePubKey:ekeys.ePubKey,
		cRecKey:ekeys.cRecKey, eRec:ekeys.eRec, eShrKey:ekeys.eShrKey,
	}

	_prvstore.user=Utils.frozenClone(user);

	return SEnclave.signin(email, password);
}

SEnclave.signin=async function(email, password) {
	if (_state.signinLock) return {error:'lock'};
	_state.signinLock=true;
	if (_prvstore.user) {
		if (_prvstore.user.email!=email) {
			await Utils.sleep(200);
			_state.signinLock=false;
			return {error:'email'}
		};
		_setState('unlocking');
		var keys=await _decryptUserKeys(_prvstore.user, password);
		if (!keys) {
			await Utils.sleep(200);
			_setState('locked');
			_state.signinLock=false;
			return {error:'password'};
		}

		for (var k in _keystore) {delete _keystore[k];}
		_keystore.ready=true;
		for(var k in keys) {_keystore[k]=keys[k];}
		_setState('unlocked');
		_state.signinLock=false;
		return _prvstore.user;
	}
	await Utils.sleep(200);
	_state.signinLock=false;
	return {error:'user'};
}

SEnclave.logout=async function() {
	if (_prvstore.state!='unlocked') return false;
	_setState('uninitialized');
	_resetMemory();
	return true;
}


// decrypt AES-GCM-256 key
async function _decryptKey(eKey, extractable) {
	if (!_keystore.ready) return false;
	try {
		var iKey=await crypt.decryptKey(
			_keystore.iPrvKey, eKey, 
			{type: 'raw', name: 'AES-GCM', length: 256, usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: false }
		);
		return iKey;
	} catch(ex) {}
	return false;
}

// create random AES-GCM-256 KEY
/*
SEnclave.generateKey=async function() {
	var iKey=await crypt.getSharedKey(
		256, {cipher: 'AES-GCM', usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }
	);
	return await crypt.cryptoToBase64(iKey);
}
*/

SEnclave.generateEncryptedKey=async function() {
	if (!_keystore.ready) return false;
	var iKey=await crypt.getSharedKey(
		256, {cipher: 'AES-GCM', usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: true }
	);
	var eKey=await crypt.encryptKey(_keystore.iPubKey, iKey);
	return eKey;
}

function _concatArrayBuffers() {
	var length=0;
	var buffers=[];
	for(var i=0,l=arguments.length;i<l;i++) {
		var buffer=false;
		var arg=arguments[i];
		var type=typeof(arg);
		if (type==='number') {
			buffer=new Uint8Array([arg]);
		} else if (type==='object') {
			type=Object.prototype.toString.call(arg);
			if (type==='[object ArrayBuffer]') {
				buffer=new Uint8Array(arg);
			} else if (type==='[object Uint8Array]') {
				buffer=arg;
			}
		}	
		if (!buffer) continue;
		length+=buffer.length
		buffers.push(buffer);
	}

	var bytea=new Uint8Array(length);
	var pos=0;
	for(var i=0,l=buffers.length;i<l;i++) {
		var buffer=buffers[i];
		bytea.set(buffer, pos);
		pos+=buffer.length;
	}
	return bytea.buffer;
}

async function _encryptRaw(data, opt) {
	var se=this;
	opt=opt||{};
	var edata=null;
	try {
		let ivAb = cryptoLib.getRandomValues(new Uint8Array(12)); // GCM is 12
		var encryptedAb = await cryptoApi.encrypt(
			{name: 'AES-GCM', iv: ivAb, tagLength: 128},
			se._key,
			data
		);
		edata=_concatArrayBuffers(ivAb, encryptedAb);
	} catch(ex) {
		console.error(ex);
	}
	return edata;
}

async function _decryptRaw(edata, opt) {
	var se=this;
	opt=opt||{};
	var data=null;
	try {
		let ivAb=new Uint8Array(edata.slice(0,12));
		edata=edata.slice(12);
		data=await cryptoApi.decrypt(
			{name: 'AES-GCM', iv: ivAb, tagLength: 128},
			se._key,
			edata
		);
	} catch {}
	return data;
}

// OBJECT > JSON > encode > encrypt > EBASE64
async function _encrypt(data) {
	var se=this;

	data=JSON.stringify(data);

	var edata=null;
	// 0: pure string, 2: lzstring
	var encodetype=2;
	var ab=null;
	switch(encodetype) {
		case 2:
			ab=LZString.compressToUint8Array(data);
			break;
		default:
			encodetype=0;
			ab=crypt.stringToArrayBuffer(data);
			break;
	}

	if (ab==null) return null;
	data=_concatArrayBuffers(encodetype, ab);
	edata=await se.encryptRaw(data);
	if (edata===null) return null;
	return crypt.arrayBufferToBase64(edata);
}

// EBASE64 > decrypt >  decode > JSON > OBJECT
async function _decrypt(edata) {
	var se=this;

	var data=null;
	try {
		var abdata=await se.decryptRaw(crypt.base64ToArrayBuffer(edata));
		var encodetype=(new Uint8Array(abdata.slice(0,1)))[0];
		abdata=abdata.slice(1);
		var str=null;
		switch(encodetype) {
			case 2:
				str=LZString.decompressFromUint8Array(new Uint8Array(abdata));
				break;
			default:
				str=crypt.arrayBufferToString(abdata);
				break;
		}
		if (str==null) return null;
		data=JSON.parse(str);
	} catch {}
	return data;
}


async function _encryptProps(obj, opt) {
	var se=this;
	var nobj={};

	opt=opt||{};

	var fn=function(prop) {
		if (prop[0]=="_") return "$"+prop.substring(1);
		return false;
	};
	for(var prop in obj) {
		var nprop=fn(prop);
		nobj[nprop || prop]=(nprop)?await se.encrypt(obj[prop]):Utils.clone(obj[prop]);
	}
	return nobj;
}

async function _decryptProps(obj, opt) {
	var se=this;
	var nobj={};

	opt=opt||{};
	var fn=function(prop) {
		if (prop[0]=="$") return "_"+prop.substring(1);
		return false;
	};

	for(var prop in obj) {
		var nprop=fn(prop);
		nobj[nprop || prop]=(nprop)?await se.decrypt(obj[prop]):Utils.clone(obj[prop]);
	}
	return nobj;
}

SEnclave.create=async function(opt) {
	var iKey=false;
	try {
		if (opt.ekey) {
			iKey=await _decryptKey(opt.ekey);
		} else if (opt.key) {
			iKey=await crypt.base64ToCrypto(opt.key, { name: 'AES-GCM', length: 256, usages: ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], isExtractable: false});
		}
	} catch {
		return false;
	}
	if (!iKey) return false;


	var se={
		_key:iKey
	};

	se.encrypt=_encrypt.bind(se);
	se.decrypt=_decrypt.bind(se);
	se.encryptProps=_encryptProps.bind(se);
	se.decryptProps=_decryptProps.bind(se);
	se.encryptRaw=_encryptRaw.bind(se);
	se.decryptRaw=_decryptRaw.bind(se);
	
	return {
		encrypt:se.encrypt,
		decrypt:se.decrypt,
		encryptProps:se.encryptProps,
		decryptProps:se.decryptProps,
		encryptRaw:se.encryptRaw,
		decryptRaw:se.decryptRaw
	};
};


export default SEnclave;