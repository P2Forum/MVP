const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));


//serialize JSON data while preserving Uint8Arrays
function serialize(data) {
  // Convert Uint8Arrays to base64 strings
  const serializedData = JSON.stringify(data, (key, value) => {
    if (value instanceof Uint8Array) {
      return { __type: 'Uint8Array', data: value.toBase64() };
      // return { __type: 'Uint8Array', data: Buffer.from(value).toString('base64') };
    }
    return value;
  },2);
  return serializedData;
}

//deserialize String of JSON data while preserving Uint8Arrays
function deserialize(string) {
  // Convert base64 strings back to Uint8Arrays
  const deserializedData = JSON.parse(string, (key, value) => {
    if (typeof value === 'object' && value !== null && value.__type === 'Uint8Array') {
      return Uint8Array.from(Uint8Array.fromBase64(value.data));
      // return Uint8Array.from(Buffer.from(value.data, 'base64'));
    }else 
      if (typeof value === 'object' && value !== null && value.__type === 'Version') {
        return new Version(value);
      }
    return value;
  });
  return deserializedData;
}

