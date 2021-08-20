/* ------------------------------------------------------------ */
/* ---- API for GET Application Natural Non Fungible Tokens --- */
/* ---------- MIT License  ------------------------------------ */
/* ------------------------------------------------------------ */

var nacl = require("tweetnacl");
var sha256 = require("sha256");
var base32 = require("base32.js");

import { Buffer } from 'buffer/';
window.Buffer = Buffer;

const SLS32=['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','2','3','4','5','6','7'];
const  poly=0x1021;

function crc16s(addr, num, crc)
{
var i,j=0;

for (; num>0; num--)             /* Step through bytes in memory */
  {
  crc = crc ^ (addr[j++] << 8);      /* Fetch byte from memory, XOR into CRC top byte*/
  for (i=0; i<8; i++)              /* Prepare to rotate 8 bits */
    {
    crc = crc << 1;                /* rotate */
    if (crc & 0x10000)             /* bit 15 was set (now bit 16)... */
      crc = (crc ^ poly) & 0xFFFF; /* XOR with XMODEM polynomic */
                                   /* and ensure CRC remains 16-bit value */
    }                              /* Loop for 8 bits */
  }                                /* Loop until num=0 */
  return(crc);                     /* Return updated CRC */
}

function base32_encode(data) {
  if (data.length < 0 || data.length > (1 << 28)) {
    return 0;
  }
  var count = 0;
  var result="";
  if (data.length > 0) {
    var buffer = data[0];
    var next = 1;
    var bitsLeft = 8;
    while (bitsLeft > 0 || next < data.length) {
      if (bitsLeft < 5) {
        if (next < data.length) {
          buffer <<= 8;
          buffer |= data[next++] & 0xFF;
          bitsLeft += 8;
        } else {
          var pad = 5 - bitsLeft;
          buffer <<= pad;
          bitsLeft += pad;
        }
      }
      var index = 0x1F & (buffer >> (bitsLeft - 5));
      bitsLeft -= 5;
      result=result+SLS32[index];count++;
    }
  }
  return result;
}

function  base32_decode(encoded) {
       var decoder = new base32.Decoder({ type: "rfc4648", lc: true});
        return decoder.write(encoded).finalize();

}

function zeroPad(num, places) {
  var zero = places - num.toString().length + 1;
  return Array(+(zero > 0 && zero)).join("0") + num;
}

function getPUBFromStr(bytes64){
  const  buff = Buffer.from(bytes64, 'hex');
  var hashHex = "30" + buff.toString('hex');  //+"0000";
  var hashBytes = Buffer.from(hashHex, 'hex');
  var crc = 0 ;
  crc = crc16s(hashBytes, 33, crc);
  crc = ((crc & 0xFF) << 8)|((crc >> 8) & 0xFF);
  var PCRC=zeroPad(crc.toString(16), 4);
  hashHex = "30" + buff.toString('hex')+ PCRC ;
  hashBytes = Buffer.from(hashHex, 'hex');
  const hashStr = base32_encode(hashBytes);
  return hashStr;
}


function getSECFromStr(bytes64){
  const  buff = Buffer.from(bytes64, 'hex');
  var hashHex = "90" + buff.toString('hex');  //+"0000";
  var hashBytes = Buffer.from(hashHex, 'hex');
  var crc = 0 ;
  crc = crc16s(hashBytes, 33, crc);
  crc = ((crc & 0xFF) << 8)|((crc >> 8) & 0xFF);
  var PCRC=zeroPad(crc.toString(16), 4);
  hashHex = "90" + buff.toString('hex')+ PCRC ;
  hashBytes = Buffer.from(hashHex, 'hex');
  const hashStr = base32_encode(hashBytes);
  return hashStr;
}


function getHashFromSEC(PRK){
  var decoder = new base32.Decoder({ type: "rfc4648", lc: true});
  var bsec = decoder.write(PRK).finalize();
  const hsec=bsec.toString('hex');
  var hashBytes = Buffer.from(hsec.substring(0,66), 'hex');
  var crc = 0 ;
  crc = crc16s(hashBytes, 33, crc);
  crc = ((crc & 0xFF) << 8)|((crc >> 8) & 0xFF);
  var PCRC=zeroPad(crc.toString(16), 4);
  if(PCRC == hsec.substring(2).substring(64))
     return hsec.substring(2).substring(0,64)
   else return "";
}

function format(data) {
  return new Buffer.from(data);
}

// (Uint8Array | String) -> String
function bytesToString(bytes) {
      if (typeof bytes === "string") {
        return bytes;
      } else {
        var str = "";
        for (var i = 0; i < bytes.length; ++i) {
          str += String.fromCharCode(bytes[i]);
        }
        return str;
      }
}

// String -> Uint8Array
function stringToBytes(string) {
      var bytes = new Uint8Array(string.length);
      for (var i = 0; i < string.length; ++i) {
        bytes[i] = string.charCodeAt(i);
      }
      return bytes;
}

// Uint8Array -> String
var toBase58 = (function() {
    var ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    return function(buffer) {
        if (buffer.length === 0) {
          return "";
        }
        var digits = [0];
        var i = 0;
        while (i < buffer.length) {
          var j = 0;
          var carry = 0;
          while (j < digits.length) {
            digits[j] <<= 8;
            j++;
          }
          digits[0] += buffer[i];
          j = 0;
          while (j < digits.length) {
            digits[j] += carry;
            carry = (digits[j] / 58) | 0;
            digits[j] %= 58;
            ++j;
          }
          while (carry) {
            digits.push(carry % 58);
            carry = (carry / 58) | 0;
          }
          i++;
        }
        i = 0;
        while (buffer[i] === 0 && i < buffer.length - 1) {
          digits.push(0);
          i++;
        }
        return digits.reverse().map(function(digit) {
          return ALPHABET[digit];
        }).join("");
      };
})();

// HexString -> Promise CID
function cid1(bytes) {
      return nanoSha256(bytes).then(function(hash) { 
        var hex = "01551220" + hash;
        var bytes = new Uint8Array(hex.length / 2);
        for (var i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
        }
        return "z" + toBase58(bytes);
      });
}

function cid2(bytes) {
      return nanoSha256(bytes).then(function(hash) { 
        var hex = "01551220" + hash;

        var bytes = new Uint8Array(hex.length / 2);
        for (var i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
        }
       var encoder = new base32.Encoder({ type: "rfc4648", lc: true });
        return "b" + encoder.write(bytes).finalize();;
      });
}

const NFTIDSZ={"MIME":undefined,"issHASH":undefined,"issCID2":undefined,"issCID1":undefined,"issCID0":undefined,"issPRK":undefined,"issPUBK":undefined};
var NFTIDS={};

function PUB2CID(issPUBK,IDS){
  IDS.issPUBK=issPUBK;
  return IDS;
};


async function b64CID(msg,MIME){
 const data=Buffer.from(msg,"base64");
 var issHASH=sha256(data);
  var HS = new Uint8Array(issHASH.length / 2);
  for (var i = 0; i < issHASH.length; i += 2) {
          HS[i / 2] = parseInt(issHASH.slice(i, i + 2), 16);
    }
  const issKeypair2 = nacl.sign.keyPair.fromSeed(HS);
  var PB1=Buffer.from(issKeypair2.publicKey).toString('hex')
  var issPUBK=getPUBFromStr(PB1);
  var hex = "01551220" + issHASH;
  var bytes = new Uint8Array(hex.length / 2);
  for (var i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
  const issCID1 = "z" + toBase58(bytes);
  var encoder = new base32.Encoder({ type: "rfc4648", lc: true });
  hex = "01551220" + issHASH;
  bytes = new Uint8Array(hex.length / 2);
        for (var i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
        }
  const issCID2 =  "b" + encoder.write(bytes).finalize();
  return {"MIME":MIME,"issHASH":issHASH,"issCID2":issCID2,"issCID1":issCID1,"issPUBK":issPUBK};
};

window.b64CID=b64CID;
