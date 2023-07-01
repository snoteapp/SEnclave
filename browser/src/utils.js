const Utils={};

const _baseChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

Utils.clone=function(o) {
	return window.structuredClone(o);
}

Utils.frozenClone=function(o) {
	return Object.freeze(Utils.clone(o));
}

// async sleep
Utils.sleep=function(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}


function _random() {
	let rnda=crypto.getRandomValues(new Uint32Array(1));
	return rnda[0] / (4294967295 + 1); // max + 1 to ensure n<1
}

function _randomInteger(bottom, top) {
	bottom=Math.max(0, bottom || 0);
	top=Math.min(Number.MAX_SAFE_INTEGER, top=top || Number.MAX_SAFE_INTEGER);
	return Math.floor( _random() * ( 1 + top - bottom ) ) + bottom;
};

Utils.unique=function(len, base) {
	len=Math.max(1, len || 20);
	base=Math.max(2, Math.min(62, base || 62))-1;

	var u='';
	for (var i=0;i<len;i++) u+=_baseChars[_randomInteger(0, base)];
	return u;
}

export default Utils