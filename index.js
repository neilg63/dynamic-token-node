/*
* Result of token decoding and authentication
*/
class ValidAuthToken {
  valid = false;
  uuid = "";
  status = "invalid";
  age = -1;

  constructor(valid = false, status = "", age = -1, uuid = "") {
    this.valid = valid === true;
    if (typeof status === "string") {
      this.status = status;
    }
    if (this.valid) {
      this.status = "ok";
    }
    if (typeof uuid === "string") {
      this.uuid = uuid;
    }
    if (age >= 0) {
      this.age = age;
    }
  }

  hasUser() {
    return typeof this.uuid === "string" && this.uuid.length > 15;
  }

}

class AuthOptions {
  apiKey = "";
  randCharsString = "%.,";
  age = 0;
  processUuid = false;
  tolerance = 300 * 1000; // 5 minutes

  constructor(apiKey = '') {
    if (typeof this.apiKey === "string") {
      this.apiKey = apiKey;
    }
  }

  shouldCheckUuid() {
    return this.processUuid;
  }

  checkUuid(ok = true) {
    this.processUuid = ok === true;
    return this;
  }

  key() {
    return this.apiKey;
  }

  hasUser() {
    return typeof this.uuid === "string" && this.uuid.length > 15;
  }

  randChars() {
    return this.randCharsString.split('');
  }

  setTolerance(millis = 0) {
    this.tolerance = millis;
    return this;
  }

  setToleranceSecs(secs = 0) {
    this.tolerance = secs * 1000;
    return this;
  }

  setToleranceMins(mins = 0) {
    this.tolerance = mins * 60 * 1000;
    return this;
  }

  /*
  * Do not use letters, numerals or underscores (_) and random split characters
  * @param {string} randStr
  * @return AuthOptions
  */
  setRandChars(randStr = "") {
    if (typeof randStr !== "string") {
      this.randCharsString = randStr;
    }
    return this;
  }

}

const toBase64 = str => Buffer.from(str).toString('base64');

const fromBase64 = str => Buffer.from(str, 'base64').toString('utf8');

const base36PartsToHexDec = (str = '') => {
  return str
    .split('_')
    .map(p => parseInt(p, 36).toString(16))
    .join('');
};

/**
* Returns a RegExp object with a character class to split on.
* @return {string[]} - Formatted, fixed length ordinal date string (eg. "91501230")
*/
const randomCharsRegex = (chars = []) => {
  return new RegExp('[' + chars + ']');
};

/**
* Returns a RegExp object with a character class to split on.
* @param str {string}
* @param chars {string[]}
* @return {string[]} - Formatted, fixed length ordinal date string (eg. "91501230")
*/
const randomCharsSplit = (str = '', chars = []) => {
  return str?.split(randomCharsRegex(chars));
};

/**
* Tests if a string contains only alphanumeric characters
* @param str {string}
* @return {boolean} 
*/
const isAlphaNum = (str = '') => {
  return /^[0-9a-z]+$/i.test(str);
}


/**
* Generates a random character from an array of letters
* @param chars {string[]}
* @return {boolean} 
*/
const randChar = (chars = []) => {
  const len = chars.length;
  const randIndex = Math.floor(Math.random() * len * 0.9999999);
  return chars[randIndex];
};

/**
* Power a number by radix 36
* @param power {number}
* @return {string} 
*/
const randInt36 = (power = 3) => {
  const randInt = Math.floor(
    Math.random() * Math.pow(10, power) * 0.9999999999
  );
  return randInt.toString(36);
};

const hexDecStringToBase36Parts = (hexDecStr) => {
  return [hexDecStr.substring(0, 12), hexDecStr.substring(12)]
    .map((hd) => parseInt(hd, 16).toString(36))
    .join("_");
};

/// Encode dynamanic with the shared api key, random characters, timestamp and optional uuid
const toDynamicKey = (options = new AuthOptions(), uid = "") => {
  const key = options.key();
  const suffixSplitChars = options.randChars();
  const addUid = uid.length > 4;
  const ts = new Date().getTime();
  const tsList = ts
    .toString(36)
    .split("")
    .reverse();
  const offset = (parseInt(tsList[0], 36) % 6) + 1;
  const uidComponent = addUid
    ? [hexDecStringToBase36Parts(uid), randInt36(3)].join(
        randChar(suffixSplitChars)
      )
    : "";
  const mergedList = tsList.map((ch, index) =>
    index === offset ? ch + key : ch
  );
  const baseStr = [mergedList.join(""), randInt36(3)].join(
    randChar(suffixSplitChars)
  );
  const keyStr = addUid ? [baseStr, uidComponent].join("__") : baseStr;
  return toBase64(keyStr);
};

/// Decode a dynamanic and extract the shared api key, timestamp and optional uuid
const fromDynamicKey = (
  str = '',
  options = new AuthOptions()
) => {
  const decrypted = fromBase64(str);
  const firstChar = decrypted.substring(0, 1);
  let uuid = '';
  let valid = false;
  let status = "invalid";
  let age = -1;
  if (isAlphaNum(firstChar)) {
    const offset = (parseInt(firstChar, 36) % 6) + 2;
    const apiKeyIndex = decrypted.indexOf(options.key());
    if (apiKeyIndex === offset) {
      const parts = decrypted.split('__');
      // check userId if required
      if (options.shouldCheckUuid() && parts.length > 1) {
        uuid = parts.pop();
        valid = false;
        const subParts = randomCharsSplit(uuid, options.randChars());
        if (subParts.length > 1) {
          const randIntStr = subParts.pop();
          const randInt = parseInt(randIntStr, 36);
          const uid36 = subParts.shift();
          uuid = base36PartsToHexDec(uid36);
          valid = uuid.length > 15;
          if (!valid) {
            status = "valid_uuid_required";
          }
          if (valid) {
            valid = !isNaN(randInt);
            status = valid ? "ok" : "uuid_security_number_missing"; 
          }
        }
      } else {
        valid = true;
        status = "ok";
      }
      const baseStr = parts.join('__');
      const tsParts = baseStr.split(options.key());
      const [tsStr, baseSuffix] = randomCharsSplit(
        tsParts.join(''),
        options.randChars(),
      );
      
      if (valid && isAlphaNum(tsStr)) {
        const suffixInt = parseInt(baseSuffix, 36);
        
        if (!isNaN(suffixInt)) {
          const ts = parseInt(
            tsStr
              .split('')
              .reverse()
              .join(''),
            36,
          );
          const currTs = new Date().getTime();
          const maxAge = options.tolerance;
          const minAge = 0 - maxAge;
          age = currTs - ts;
          valid = age >= minAge && age <= maxAge;
          status = valid ?  "ok" : "timed_out";
        }
      }
    } else {
      status = apiKeyIndex < 0 ? "unmatched_api_key" : "misplaced_api_key";
    }
  }
  return new ValidAuthToken(valid, status, age, uuid);
};

function delay(ms = 0) {
  return new Promise(res => setTimeout(res, ms));
}

function text_generation() {
  const options = new AuthOptions("Magna;Carta123").setToleranceMins(2).checkUuid(true).setToleranceSecs(1);
  
  const to_key = toDynamicKey(options, "5d00012de43dcd165cceb295");

  const result = fromDynamicKey(to_key, options);

  console.log(to_key, result);

  delay(3000).then(() => {
    const result2 = fromDynamicKey(to_key, options);
    console.log(to_key, result2);
  })

}

text_generation();