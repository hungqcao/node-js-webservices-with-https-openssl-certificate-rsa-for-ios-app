module.exports = {
  copyData : function name(source, params) {
	if(params){
		for(var prop in params){
			if(params.hasOwnProperty(prop)){
				source[prop] = params[prop];
			}
		}
	}else{
		throw "Object is null!";
	}
  },
  encryptData : function name(source, key, padding) {
	if(key){
		for(var prop in source){
			if(source.hasOwnProperty(prop)){
				source[prop] = key.encrypt(source[prop], 'utf8', 'base64');
			}
		}
	}else{
		throw "Key is null!";
	}
  }
};