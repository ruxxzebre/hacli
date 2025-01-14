module.exports.has = function has(obj, key) {
  return obj != null && hasOwnProperty.call(obj, key);
};

module.exports.get = function get(obj, desc, value) {
  var arr = desc ? desc.split(".") : [];

  while (arr.length && obj) {
    var comp = arr.shift();
    var match = new RegExp("(.+)\\[([0-9]*)\\]").exec(comp);

    // handle arrays
    if ((match !== null) && (match.length == 3)) {
      var arrayData = {
        arrName: match[1],
        arrIndex: match[2]
      };
      if (obj[arrayData.arrName] !== undefined) {
        obj = obj[arrayData.arrName][arrayData.arrIndex];
      } else {
        obj = undefined;
      }

      continue;
    }

    obj = obj[comp];
  }

  if (typeof value !== 'undefined') {
    if (obj === undefined) {
      return value;
    }
  }

  return obj;
}