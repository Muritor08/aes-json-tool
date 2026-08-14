import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import CryptoJS from "crypto-js";
import JSON5 from "json5";
import "./styles.css";

/*
|--------------------------------------------------------------------------
| UNIVERSAL AES ENCRYPTION TOOL
|--------------------------------------------------------------------------
|
| Key sizes:
|   AES-128
|   AES-192
|   AES-256
|
| Modes:
|   AES-CBC
|   AES-ECB
|   AES-CFB
|   AES-OFB
|   AES-CTR
|   AES-GCM
|
| Padding:
|   PKCS7
|   PKCS5
|   ANSI X9.23
|   ISO/IEC 7816-4
|   ISO 10126
|   Zero Padding
|   No Padding
|
| Input:
|   Raw text
|   JSON
|   JSONC
|
| JSON scope:
|   Entire Input / JSON
|   All JSON Values
|   Specific JSON Values
|
| IV:
|   Auto Generate
|   Extract From Input
|   Manual
|
| Finarkein:
|
|   AES-256-CBC
|   UTF-8 key
|   PKCS7
|   Random 16-byte IV per field
|   Base64( IV[16 bytes] || Ciphertext )
|
|--------------------------------------------------------------------------
*/

const KEY_BYTES = {
  "128": 16,
  "192": 24,
  "256": 32,
};

const MODE_CONFIG = {
  CBC: {
    ivSize: 16,
    blockMode: true,
    supportsPadding: true,
  },

  ECB: {
    ivSize: 0,
    blockMode: true,
    supportsPadding: true,
  },

  CFB: {
    ivSize: 16,
    blockMode: false,
    supportsPadding: false,
  },

  OFB: {
    ivSize: 16,
    blockMode: false,
    supportsPadding: false,
  },

  CTR: {
    ivSize: 16,
    blockMode: false,
    supportsPadding: false,
  },

  GCM: {
    ivSize: 12,
    blockMode: false,
    supportsPadding: false,
  },
};

const PADDINGS = [
  {
    value: "PKCS7",
    label: "PKCS7",
  },
  {
    value: "PKCS5",
    label: "PKCS5",
  },
  {
    value: "X923",
    label: "ANSI X9.23",
  },
  {
    value: "ISO7816",
    label: "ISO/IEC 7816-4",
  },
  {
    value: "ISO10126",
    label: "ISO 10126",
  },
  {
    value: "ZERO",
    label: "Zero Padding",
  },
  {
    value: "NONE",
    label: "No Padding",
  },
];

/* =========================================================================
   BYTE HELPERS
========================================================================= */

function utf8ToBytes(value) {
  return new TextEncoder().encode(value);
}

function bytesToUtf8(value) {
  return new TextDecoder().decode(value);
}

function randomBytes(length) {
  const result = new Uint8Array(length);
  crypto.getRandomValues(result);
  return result;
}

function concatBytes(...arrays) {
  const total = arrays.reduce(
    (sum, array) => sum + array.length,
    0
  );

  const result = new Uint8Array(total);

  let offset = 0;

  for (const array of arrays) {
    result.set(array, offset);
    offset += array.length;
  }

  return result;
}

function bytesToBase64(bytes) {
  let binary = "";

  for (
    let i = 0;
    i < bytes.length;
    i += 0x8000
  ) {
    binary += String.fromCharCode(
      ...bytes.subarray(
        i,
        Math.min(
          i + 0x8000,
          bytes.length
        )
      )
    );
  }

  return btoa(binary);
}

function base64ToBytes(value) {
  const clean = value
    .replace(/\s+/g, "")
    .trim();

  if (!clean) {
    throw new Error(
      "Base64 input is empty."
    );
  }

  let binary;

  try {
    binary = atob(clean);
  } catch {
    throw new Error(
      "Invalid Base64 input."
    );
  }

  const result =
    new Uint8Array(
      binary.length
    );

  for (
    let i = 0;
    i < binary.length;
    i++
  ) {
    result[i] =
      binary.charCodeAt(i);
  }

  return result;
}

function hexToBytes(value) {
  const clean = value
    .trim()
    .replace(/^0x/i, "");

  if (
    !/^[0-9a-fA-F]*$/.test(clean)
  ) {
    throw new Error(
      "Invalid hexadecimal input."
    );
  }

  if (
    clean.length % 2 !== 0
  ) {
    throw new Error(
      "Hexadecimal input must contain an even number of characters."
    );
  }

  const result =
    new Uint8Array(
      clean.length / 2
    );

  for (
    let i = 0;
    i < clean.length;
    i += 2
  ) {
    result[i / 2] =
      parseInt(
        clean.substring(
          i,
          i + 2
        ),
        16
      );
  }

  return result;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(
      (byte) =>
        byte
          .toString(16)
          .padStart(2, "0")
    )
    .join("");
}

function decodeBytes(
  value,
  encoding
) {
  switch (encoding) {
    case "UTF8":
      return utf8ToBytes(
        value
      );

    case "BASE64":
      return base64ToBytes(
        value
      );

    case "HEX":
      return hexToBytes(
        value
      );

    default:
      throw new Error(
        `Unsupported encoding: ${encoding}`
      );
  }
}

function encodeBytes(
  value,
  encoding
) {
  switch (encoding) {
    case "UTF8":
      return bytesToUtf8(
        value
      );

    case "BASE64":
      return bytesToBase64(
        value
      );

    case "HEX":
      return bytesToHex(
        value
      );

    default:
      throw new Error(
        `Unsupported encoding: ${encoding}`
      );
  }
}

/* =========================================================================
   CRYPTOJS WORDARRAY HELPERS
========================================================================= */

function bytesToWordArray(
  bytes
) {
  const words = [];

  for (
    let i = 0;
    i < bytes.length;
    i += 4
  ) {
    words[i >>> 2] =
      ((bytes[i] || 0) << 24) |
      ((bytes[i + 1] || 0) << 16) |
      ((bytes[i + 2] || 0) << 8) |
      (bytes[i + 3] || 0);
  }

  return CryptoJS.lib.WordArray.create(
    words,
    bytes.length
  );
}

function wordArrayToBytes(
  wordArray
) {
  const result =
    new Uint8Array(
      wordArray.sigBytes
    );

  for (
    let i = 0;
    i < wordArray.sigBytes;
    i++
  ) {
    result[i] =
      (wordArray.words[
        i >>> 2
      ] >>>
        (24 -
          (i % 4) * 8)) &
      0xff;
  }

  return result;
}

/* =========================================================================
   KEY
========================================================================= */

function getKeyBytes(
  secretKey,
  keyEncoding,
  keySize
) {
  if (
    !secretKey.trim()
  ) {
    throw new Error(
      "Secret key is required."
    );
  }

  const result =
    decodeBytes(
      secretKey,
      keyEncoding
    );

  const expected =
    KEY_BYTES[
      String(keySize)
    ];

  if (
    expected === undefined
  ) {
    throw new Error(
      `Unsupported AES key size: ${keySize}.`
    );
  }

  if (
    result.length !==
    expected
  ) {
    throw new Error(
      `AES-${keySize} requires exactly ${expected} bytes. ` +
        `Received ${result.length} bytes.`
    );
  }

  return result;
}

/* =========================================================================
   PADDING
========================================================================= */

function padBytes(
  input,
  padding
) {
  const data =
    new Uint8Array(
      input
    );

  const blockSize = 16;

  if (
    padding ===
    "NONE"
  ) {
    if (
      data.length %
        blockSize !==
      0
    ) {
      throw new Error(
        "No Padding requires plaintext length to be a multiple of 16 bytes."
      );
    }

    return data;
  }

  const remainder =
    data.length %
    blockSize;

  let paddingLength =
    blockSize -
    remainder;

  /*
   * PKCS7 / PKCS5
   */
  if (
    padding === "PKCS7" ||
    padding === "PKCS5"
  ) {
    const result =
      new Uint8Array(
        data.length +
          paddingLength
      );

    result.set(data);

    result.fill(
      paddingLength,
      data.length
    );

    return result;
  }

  /*
   * Zero Padding
   */
  if (
    padding === "ZERO"
  ) {
    /*
     * Don't add an extra block if
     * already block-aligned.
     */
    if (
      remainder === 0
    ) {
      return data;
    }

    const result =
      new Uint8Array(
        data.length +
          paddingLength
      );

    result.set(data);

    return result;
  }

  /*
   * ANSI X9.23
   */
  if (
    padding === "X923"
  ) {
    const result =
      new Uint8Array(
        data.length +
          paddingLength
      );

    result.set(data);

    result[
      result.length - 1
    ] = paddingLength;

    return result;
  }

  /*
   * ISO/IEC 7816-4
   */
  if (
    padding ===
    "ISO7816"
  ) {
    const result =
      new Uint8Array(
        data.length +
          paddingLength
      );

    result.set(data);

    result[
      data.length
    ] = 0x80;

    return result;
  }

  /*
   * ISO 10126
   */
  if (
    padding ===
    "ISO10126"
  ) {
    const result =
      new Uint8Array(
        data.length +
          paddingLength
      );

    result.set(data);

    if (
      paddingLength > 1
    ) {
      result.set(
        randomBytes(
          paddingLength - 1
        ),
        data.length
      );
    }

    result[
      result.length - 1
    ] = paddingLength;

    return result;
  }

  throw new Error(
    `Unsupported padding: ${padding}`
  );
}

function unpadBytes(
  input,
  padding
) {
  const data =
    new Uint8Array(
      input
    );

  if (
    padding ===
    "NONE"
  ) {
    return data;
  }

  if (
    data.length === 0
  ) {
    return data;
  }

  /*
   * PKCS7 / PKCS5
   */
  if (
    padding === "PKCS7" ||
    padding === "PKCS5"
  ) {
    const paddingLength =
      data[
        data.length - 1
      ];

    if (
      paddingLength < 1 ||
      paddingLength > 16 ||
      paddingLength >
        data.length
    ) {
      throw new Error(
        "Invalid PKCS7 padding."
      );
    }

    for (
      let i =
        data.length -
        paddingLength;
      i < data.length;
      i++
    ) {
      if (
        data[i] !==
        paddingLength
      ) {
        throw new Error(
          "Invalid PKCS7 padding."
        );
      }
    }

    return data.slice(
      0,
      data.length -
        paddingLength
    );
  }

  /*
   * Zero Padding
   */
  if (
    padding ===
    "ZERO"
  ) {
    let end =
      data.length;

    while (
      end > 0 &&
      data[end - 1] === 0
    ) {
      end--;
    }

    return data.slice(
      0,
      end
    );
  }

  /*
   * ISO/IEC 7816-4
   */
  if (
    padding ===
    "ISO7816"
  ) {
    let index =
      data.length - 1;

    while (
      index >= 0 &&
      data[index] === 0
    ) {
      index--;
    }

    if (
      index < 0 ||
      data[index] !==
        0x80
    ) {
      throw new Error(
        "Invalid ISO/IEC 7816-4 padding."
      );
    }

    return data.slice(
      0,
      index
    );
  }

  /*
   * ANSI X9.23
   */
  if (
    padding ===
    "X923"
  ) {
    const paddingLength =
      data[
        data.length - 1
      ];

    if (
      paddingLength < 1 ||
      paddingLength > 16 ||
      paddingLength >
        data.length
    ) {
      throw new Error(
        "Invalid ANSI X9.23 padding."
      );
    }

    for (
      let i =
        data.length -
        paddingLength;
      i <
        data.length - 1;
      i++
    ) {
      if (
        data[i] !== 0
      ) {
        throw new Error(
          "Invalid ANSI X9.23 padding."
        );
      }
    }

    return data.slice(
      0,
      data.length -
        paddingLength
    );
  }

  /*
   * ISO 10126
   */
  if (
    padding ===
    "ISO10126"
  ) {
    const paddingLength =
      data[
        data.length - 1
      ];

    if (
      paddingLength < 1 ||
      paddingLength > 16 ||
      paddingLength >
        data.length
    ) {
      throw new Error(
        "Invalid ISO 10126 padding."
      );
    }

    return data.slice(
      0,
      data.length -
        paddingLength
    );
  }

  throw new Error(
    `Unsupported padding: ${padding}`
  );
}

/* =========================================================================
   AES CBC / ECB
========================================================================= */

function encryptCBC(
  plaintext,
  key,
  iv,
  padding
) {
  const padded =
    padBytes(
      plaintext,
      padding
    );

  const encrypted =
    CryptoJS.AES.encrypt(
      bytesToWordArray(
        padded
      ),
      bytesToWordArray(
        key
      ),
      {
        mode:
          CryptoJS.mode.CBC,
        iv:
          bytesToWordArray(
            iv
          ),
        padding:
          CryptoJS.pad
            .NoPadding,
      }
    );

  return wordArrayToBytes(
    encrypted.ciphertext
  );
}

function decryptCBC(
  ciphertext,
  key,
  iv,
  padding
) {
  const decrypted =
    CryptoJS.AES.decrypt(
      {
        ciphertext:
          bytesToWordArray(
            ciphertext
          ),
      },
      bytesToWordArray(
        key
      ),
      {
        mode:
          CryptoJS.mode.CBC,
        iv:
          bytesToWordArray(
            iv
          ),
        padding:
          CryptoJS.pad
            .NoPadding,
      }
    );

  return unpadBytes(
    wordArrayToBytes(
      decrypted
    ),
    padding
  );
}

function encryptECB(
  plaintext,
  key,
  padding
) {
  const padded =
    padBytes(
      plaintext,
      padding
    );

  const encrypted =
    CryptoJS.AES.encrypt(
      bytesToWordArray(
        padded
      ),
      bytesToWordArray(
        key
      ),
      {
        mode:
          CryptoJS.mode.ECB,
        padding:
          CryptoJS.pad
            .NoPadding,
      }
    );

  return wordArrayToBytes(
    encrypted.ciphertext
  );
}

function decryptECB(
  ciphertext,
  key,
  padding
) {
  const decrypted =
    CryptoJS.AES.decrypt(
      {
        ciphertext:
          bytesToWordArray(
            ciphertext
          ),
      },
      bytesToWordArray(
        key
      ),
      {
        mode:
          CryptoJS.mode.ECB,
        padding:
          CryptoJS.pad
            .NoPadding,
      }
    );

  return unpadBytes(
    wordArrayToBytes(
      decrypted
    ),
    padding
  );
}

/* =========================================================================
   AES CFB / OFB / CTR
========================================================================= */

function encryptCFB(
  plaintext,
  key,
  iv
) {
  const encrypted =
    CryptoJS.AES.encrypt(
      bytesToWordArray(
        plaintext
      ),
      bytesToWordArray(
        key
      ),
      {
        mode:
          CryptoJS.mode.CFB,
        iv:
          bytesToWordArray(
            iv
          ),
        padding:
          CryptoJS.pad
            .NoPadding,
      }
    );

  return wordArrayToBytes(
    encrypted.ciphertext
  );
}

function decryptCFB(
  ciphertext,
  key,
  iv
) {
  const decrypted =
    CryptoJS.AES.decrypt(
      {
        ciphertext:
          bytesToWordArray(
            ciphertext
          ),
      },
      bytesToWordArray(
        key
      ),
      {
        mode:
          CryptoJS.mode.CFB,
        iv:
          bytesToWordArray(
            iv
          ),
        padding:
          CryptoJS.pad
            .NoPadding,
      }
    );

  return wordArrayToBytes(
    decrypted
  );
}

function encryptOFB(
  plaintext,
  key,
  iv
) {
  const encrypted =
    CryptoJS.AES.encrypt(
      bytesToWordArray(
        plaintext
      ),
      bytesToWordArray(
        key
      ),
      {
        mode:
          CryptoJS.mode.OFB,
        iv:
          bytesToWordArray(
            iv
          ),
        padding:
          CryptoJS.pad
            .NoPadding,
      }
    );

  return wordArrayToBytes(
    encrypted.ciphertext
  );
}

function decryptOFB(
  ciphertext,
  key,
  iv
) {
  const decrypted =
    CryptoJS.AES.decrypt(
      {
        ciphertext:
          bytesToWordArray(
            ciphertext
          ),
      },
      bytesToWordArray(
        key
      ),
      {
        mode:
          CryptoJS.mode.OFB,
        iv:
          bytesToWordArray(
            iv
          ),
        padding:
          CryptoJS.pad
            .NoPadding,
      }
    );

  return wordArrayToBytes(
    decrypted
  );
}

function encryptCTR(
  plaintext,
  key,
  iv
) {
  const encrypted =
    CryptoJS.AES.encrypt(
      bytesToWordArray(
        plaintext
      ),
      bytesToWordArray(
        key
      ),
      {
        mode:
          CryptoJS.mode.CTR,
        iv:
          bytesToWordArray(
            iv
          ),
        padding:
          CryptoJS.pad
            .NoPadding,
      }
    );

  return wordArrayToBytes(
    encrypted.ciphertext
  );
}

function decryptCTR(
  ciphertext,
  key,
  iv
) {
  const decrypted =
    CryptoJS.AES.decrypt(
      {
        ciphertext:
          bytesToWordArray(
            ciphertext
          ),
      },
      bytesToWordArray(
        key
      ),
      {
        mode:
          CryptoJS.mode.CTR,
        iv:
          bytesToWordArray(
            iv
          ),
        padding:
          CryptoJS.pad
            .NoPadding,
      }
    );

  return wordArrayToBytes(
    decrypted
  );
}

/* =========================================================================
   AES GCM
========================================================================= */

async function encryptGCM(
  plaintext,
  key,
  iv
) {
  const cryptoKey =
    await crypto.subtle.importKey(
      "raw",
      key,
      {
        name:
          "AES-GCM",
      },
      false,
      ["encrypt"]
    );

  const encrypted =
    await crypto.subtle.encrypt(
      {
        name:
          "AES-GCM",
        iv,
        tagLength: 128,
      },
      cryptoKey,
      plaintext
    );

  return new Uint8Array(
    encrypted
  );
}

async function decryptGCM(
  ciphertext,
  key,
  iv
) {
  const cryptoKey =
    await crypto.subtle.importKey(
      "raw",
      key,
      {
        name:
          "AES-GCM",
      },
      false,
      ["decrypt"]
    );

  const decrypted =
    await crypto.subtle.decrypt(
      {
        name:
          "AES-GCM",
        iv,
        tagLength: 128,
      },
      cryptoKey,
      ciphertext
    );

  return new Uint8Array(
    decrypted
  );
}

/* =========================================================================
   IV
========================================================================= */

function generateIV(
  mode
) {
  const size =
    MODE_CONFIG[
      mode
    ].ivSize;

  if (!size) {
    return new Uint8Array(0);
  }

  return randomBytes(
    size
  );
}

function validateIV(
  iv,
  mode
) {
  const expected =
    MODE_CONFIG[
      mode
    ].ivSize;

  if (
    expected === 0
  ) {
    return;
  }

  if (
    !iv ||
    iv.length !== expected
  ) {
    throw new Error(
      `${mode} requires an IV of ${expected} bytes.`
    );
  }
}

/* =========================================================================
   CORE ENCRYPTION
========================================================================= */

async function encryptBytes({
  plaintext,
  key,
  mode,
  padding,
  iv,
}) {
  if (
    mode === "CBC"
  ) {
    return encryptCBC(
      plaintext,
      key,
      iv,
      padding
    );
  }

  if (
    mode === "ECB"
  ) {
    return encryptECB(
      plaintext,
      key,
      padding
    );
  }

  if (
    mode === "CFB"
  ) {
    return encryptCFB(
      plaintext,
      key,
      iv
    );
  }

  if (
    mode === "OFB"
  ) {
    return encryptOFB(
      plaintext,
      key,
      iv
    );
  }

  if (
    mode === "CTR"
  ) {
    return encryptCTR(
      plaintext,
      key,
      iv
    );
  }

  if (
    mode === "GCM"
  ) {
    return encryptGCM(
      plaintext,
      key,
      iv
    );
  }

  throw new Error(
    `Unsupported AES mode: ${mode}`
  );
}

/* =========================================================================
   CORE DECRYPTION
========================================================================= */

async function decryptBytes({
  ciphertext,
  key,
  mode,
  padding,
  iv,
}) {
  if (
    mode === "CBC"
  ) {
    return decryptCBC(
      ciphertext,
      key,
      iv,
      padding
    );
  }

  if (
    mode === "ECB"
  ) {
    return decryptECB(
      ciphertext,
      key,
      padding
    );
  }

  if (
    mode === "CFB"
  ) {
    return decryptCFB(
      ciphertext,
      key,
      iv
    );
  }

  if (
    mode === "OFB"
  ) {
    return decryptOFB(
      ciphertext,
      key,
      iv
    );
  }

  if (
    mode === "CTR"
  ) {
    return decryptCTR(
      ciphertext,
      key,
      iv
    );
  }

  if (
    mode === "GCM"
  ) {
    return decryptGCM(
      ciphertext,
      key,
      iv
    );
  }

  throw new Error(
    `Unsupported AES mode: ${mode}`
  );
}

/* =========================================================================
   JSON
========================================================================= */

function parseJSONInput(
  input
) {
  if (
    !input ||
    !input.trim()
  ) {
    return {
      valid: false,
      value: null,
    };
  }

  try {
    return {
      valid: true,
      value: JSON5.parse(
        input.replace(
          /^\uFEFF/,
          ""
        )
      ),
    };
  } catch {
    return {
      valid: false,
      value: null,
    };
  }
}

function isContainer(
  value
) {
  return (
    value !== null &&
    typeof value ===
      "object"
  );
}

/*
 * Produces ONE entry per object/array branch
 * and ONE entry per primitive value.
 *
 * No duplicates.
 */
function collectJSONPaths(
  value,
  path = "",
  output = []
) {
  /*
   * Primitive
   */
  if (
    !isContainer(value)
  ) {
    output.push({
      path: path || "$",
      type: "value",
      value,
    });

    return output;
  }

  /*
   * Object
   */
  if (
    !Array.isArray(value)
  ) {
    for (
      const [key, child] of
      Object.entries(value)
    ) {
      const childPath =
        path
          ? `${path}.${key}`
          : key;

      if (
        isContainer(child)
      ) {
        output.push({
          path: childPath,
          type: "branch",
          value: child,
        });

        collectJSONPaths(
          child,
          childPath,
          output
        );
      } else {
        output.push({
          path: childPath,
          type: "value",
          value: child,
        });
      }
    }

    return output;
  }

  /*
   * Array
   */
  value.forEach(
    (child, index) => {
      const childPath =
        `${path}[${index}]`;

      if (
        isContainer(child)
      ) {
        output.push({
          path: childPath,
          type: "branch",
          value: child,
        });

        collectJSONPaths(
          child,
          childPath,
          output
        );
      } else {
        output.push({
          path: childPath,
          type: "value",
          value: child,
        });
      }
    }
  );

  return output;
}

/* =========================================================================
   CORRECT JSON PATH FUNCTIONS
========================================================================= */

function getAtPath(
  root,
  path
) {
  if (
    path === "$"
  ) {
    return root;
  }

  const tokens =
    path
      .replace(
        /\[(\d+)\]/g,
        ".$1"
      )
      .split(".")
      .filter(Boolean);

  let current =
    root;

  for (
    const token of tokens
  ) {
    current =
      current[token];
  }

  return current;
}

function setAtPath(
  root,
  path,
  value
) {
  if (
    path === "$"
  ) {
    return value;
  }

  const tokens =
    path
      .replace(
        /\[(\d+)\]/g,
        ".$1"
      )
      .split(".")
      .filter(Boolean);

  let current =
    root;

  for (
    let i = 0;
    i <
    tokens.length - 1;
    i++
  ) {
    current =
      current[
        tokens[i]
      ];
  }

  current[
    tokens[
      tokens.length - 1
    ]
  ] = value;

  return root;
}

function cloneJSON(
  value
) {
  return JSON.parse(
    JSON.stringify(
      value
    )
  );
}

function pathMatches(
  candidate,
  selected
) {
  return (
    candidate === selected ||
    candidate.startsWith(
      `${selected}.`
    ) ||
    candidate.startsWith(
      `${selected}[`
    )
  );
}

/* =========================================================================
   APP
========================================================================= */

function App() {
  const STORAGE_KEY = "universal-aes-tool-state-v1";

  const savedState = (() => {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : {};
    } catch {
      return {};
    }
  })();

  const [
    operation,
    setOperation,
  ] =
    useState(
      savedState.operation ||
        "decrypt"
    );

  const [
    keySize,
    setKeySize,
  ] =
    useState(
      savedState.keySize ||
        "256"
    );

  const [
    mode,
    setMode,
  ] =
    useState(
      savedState.mode ||
        "CBC"
    );

  const [
    padding,
    setPadding,
  ] =
    useState(
      savedState.padding ||
        "PKCS7"
    );

  const [
    secretKey,
    setSecretKey,
  ] =
    useState(
      savedState.secretKey ||
        ""
    );

  const [
    showKey,
    setShowKey,
  ] =
    useState(
      savedState.showKey ??
        false
    );

  const [
    keyEncoding,
    setKeyEncoding,
  ] =
    useState(
      savedState.keyEncoding ||
        "UTF8"
    );

  const [
    inputEncoding,
    setInputEncoding,
  ] =
    useState(
      savedState.inputEncoding ||
        "BASE64"
    );

  const [
    outputEncoding,
    setOutputEncoding,
  ] =
    useState(
      savedState.outputEncoding ||
        "BASE64"
    );

  const [
    ivHandling,
    setIvHandling,
  ] =
    useState(
      savedState.ivHandling ||
        "EXTRACT"
    );

  const [
    ivSize,
    setIvSize,
  ] =
    useState(
      savedState.ivSize ??
        16
    );

  const [
    manualIV,
    setManualIV,
  ] =
    useState(
      savedState.manualIV ||
        ""
    );

  const [
    ivEncoding,
    setIvEncoding,
  ] =
    useState(
      savedState.ivEncoding ||
        "BASE64"
    );

  const [
    prependIv,
    setPrependIv,
  ] =
    useState(
      savedState.prependIv ??
        true
    );

  const [
    input,
    setInput,
  ] =
    useState(
      savedState.input ||
        ""
    );

  const [
    output,
    setOutput,
  ] =
    useState(
      savedState.output ||
        ""
    );

  const [
    scope,
    setScope,
  ] =
    useState(
      savedState.scope ||
        "SPECIFIC"
    );

  const [
    selectedPaths,
    setSelectedPaths,
  ] =
    useState(
      savedState.selectedPaths ||
        []
    );

  const [
    processing,
    setProcessing,
  ] =
    useState(false);

  const [
    error,
    setError,
  ] =
    useState("");

  const [
    success,
    setSuccess,
  ] =
    useState("");

  /*
   * Parse input as JSON5.
   *
   * This accepts normal JSON as well as your
   * commented JSON example.
   */
  const parsed =
    useMemo(
      () =>
        parseJSONInput(
          input
        ),
      [input]
    );

  const isJSON =
    parsed.valid &&
    isContainer(
      parsed.value
    );

  const jsonPaths =
    useMemo(
      () =>
        isJSON
          ? collectJSONPaths(
              parsed.value
            )
          : [],
      [
        isJSON,
        parsed.value,
      ]
    );

  const currentMode =
    MODE_CONFIG[mode];

  useEffect(() => {
    try {
      sessionStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({
          operation,
          keySize,
          mode,
          padding,
          secretKey,
          showKey,
          keyEncoding,
          inputEncoding,
          outputEncoding,
          ivHandling,
          ivSize,
          manualIV,
          ivEncoding,
          prependIv,
          input,
          output,
          scope,
          selectedPaths,
        })
      );
    } catch (storageError) {
      console.warn(
        "Unable to persist AES tool state.",
        storageError
      );
    }
  }, [
    operation,
    keySize,
    mode,
    padding,
    secretKey,
    showKey,
    keyEncoding,
    inputEncoding,
    outputEncoding,
    ivHandling,
    ivSize,
    manualIV,
    ivEncoding,
    prependIv,
    input,
    output,
    scope,
    selectedPaths,
  ]);

  function clearMessages() {
    setError("");
    setSuccess("");
  }

  function clearOutput() {
    setOutput("");
  }

  function handleInputChange(
    value
  ) {
    setInput(value);

    setSelectedPaths([]);

    clearMessages();
  }

  function handleOperationChange(
    value
  ) {
    /*
     * IMPORTANT:
     * Changing Encrypt <-> Decrypt must NOT
     * silently change the user's IV configuration.
     *
     * Example:
     *   Manual IV + Ciphertext Only
     * must remain Manual IV + Ciphertext Only
     * when switching operations or using reverse
     * processing.
     */
    setOperation(value);

    setError("");
    setSuccess("");
  }

  function handleModeChange(
    value
  ) {
    setMode(value);

    if (
      value === "CBC" ||
      value === "ECB"
    ) {
      setPadding(
        "PKCS7"
      );
    } else {
      setPadding(
        "NONE"
      );
    }

    if (
      value === "GCM"
    ) {
      setIvSize(12);
    } else if (
      value === "ECB"
    ) {
      setIvSize(0);
    } else {
      setIvSize(16);
    }

    clearMessages();
  }

  function getEncryptionIV() {
    if (
      mode === "ECB"
    ) {
      return new Uint8Array(
        0
      );
    }

    if (
      ivHandling ===
      "MANUAL"
    ) {
      const iv =
        decodeBytes(
          manualIV,
          ivEncoding
        );

      validateIV(
        iv,
        mode
      );

      return iv;
    }

    /*
     * IMPORTANT:
     * This gets called independently
     * for each selected JSON value.
     */
    return generateIV(
      mode
    );
  }

  async function encryptValue(
    value
  ) {
    if (
      value === ""
    ) {
      return "";
    }

    const key =
      getKeyBytes(
        secretKey,
        keyEncoding,
        keySize
      );

    const iv =
      getEncryptionIV();

    const plaintext =
      utf8ToBytes(
        value
      );

    const ciphertext =
      await encryptBytes({
        plaintext,
        key,
        mode,
        padding,
        iv,
      });

    /*
     * IMPORTANT:
     * IV transport is controlled ONLY by the
     * "IV / Ciphertext Layout" setting.
     *
     * IV + Ciphertext:
     *   output = IV || ciphertext
     *
     * Ciphertext Only:
     *   output = ciphertext
     *
     * This is especially important for APIs that
     * use a fixed/manual IV and expect Base64 of
     * ciphertext only (for example Contract Note).
     */
    let outputBytes = ciphertext;

    if (
      mode !== "ECB" &&
      prependIv === true
    ) {
      outputBytes = concatBytes(
        iv,
        ciphertext
      );
    }

    return encodeBytes(
      outputBytes,
      outputEncoding
    );
  }

  async function decryptValue(
    value
  ) {
    if (
      value === ""
    ) {
      return "";
    }

    const key =
      getKeyBytes(
        secretKey,
        keyEncoding,
        keySize
      );

    const encoded =
      decodeBytes(
        value,
        inputEncoding
      );

    let iv =
      new Uint8Array(
        0
      );

    let ciphertext =
      encoded;

    /*
     * ECB:
     * no IV.
     */
    if (
      mode === "ECB"
    ) {
      iv =
        new Uint8Array(
          0
        );
    }

    /*
     * Manual IV.
     */
    else if (
      ivHandling ===
      "MANUAL"
    ) {
      iv =
        decodeBytes(
          manualIV,
          ivEncoding
        );

      validateIV(
        iv,
        mode
      );
    }

    /*
     * Extract IV from Base64/Hex.
     *
     * Finarkein:
     *
     * decoded[0..15]  = IV
     * decoded[16..]   = ciphertext
     */
    else {
      if (
        !prependIv
      ) {
        throw new Error(
          "Extract From Input requires IV + Ciphertext layout."
        );
      }

      if (
        encoded.length <=
        currentMode.ivSize
      ) {
        throw new Error(
          `Encrypted input is too short. Expected ${currentMode.ivSize} IV bytes followed by ciphertext.`
        );
      }

      iv =
        encoded.slice(
          0,
          currentMode.ivSize
        );

      ciphertext =
        encoded.slice(
          currentMode.ivSize
        );
    }

    /*
     * CBC / ECB require complete AES blocks.
     */
    if (
      (
        mode === "CBC" ||
        mode === "ECB"
      ) &&
      ciphertext.length %
        16 !==
        0
    ) {
      throw new Error(
        `Invalid ciphertext length: ${ciphertext.length} bytes. AES-${mode} ciphertext must be a multiple of 16 bytes.`
      );
    }

    const plaintext =
      await decryptBytes({
        ciphertext,
        key,
        mode,
        padding,
        iv,
      });

    return bytesToUtf8(
      plaintext
    );
  }

  async function processJSONValues(
    operationOverride = operation
  ) {
    const result =
      cloneJSON(
        parsed.value
      );

    let pathsToProcess = [];

    /*
     * ALL JSON VALUES
     */
    if (
      scope ===
      "ALL_VALUES"
    ) {
      pathsToProcess =
        jsonPaths
          .filter(
            (item) =>
              item.type ===
              "value"
          )
          .map(
            (item) =>
              item.path
          );
    }

    /*
     * SPECIFIC JSON VALUES
     */
    if (
      scope ===
      "SPECIFIC"
    ) {
      pathsToProcess =
        jsonPaths
          .filter(
            (item) => {
              if (
                item.type !==
                "value"
              ) {
                return false;
              }

              return selectedPaths.some(
                (selected) =>
                  pathMatches(
                    item.path,
                    selected
                  )
              );
            }
          )
          .map(
            (item) =>
              item.path
          );
    }

    if (
      pathsToProcess.length ===
      0
    ) {
      throw new Error(
        "No JSON values were selected."
      );
    }

    /*
     * Process each selected value individually.
     *
     * This is important for Finarkein:
     *
     * every field gets a new IV.
     */
    for (
      const path of
      pathsToProcess
    ) {
      const original =
        getAtPath(
          result,
          path
        );

      /*
       * Keep empty/null values unchanged.
       */
      if (
        original ===
          "" ||
        original ===
          null ||
        original ===
          undefined
      ) {
        continue;
      }

      /*
       * Convert non-string primitives to
       * JSON text so they can be restored.
       */
      const plainText =
        typeof original ===
        "string"
          ? original
          : JSON.stringify(
              original
            );

      if (
        operationOverride ===
        "encrypt"
      ) {
        const encrypted =
          await encryptValue(
            plainText
          );

        setAtPath(
          result,
          path,
          encrypted
        );
      } else {
        const decrypted =
          await decryptValue(
            plainText
          );

        /*
         * Attempt to restore numbers,
         * booleans and null.
         */
        try {
          setAtPath(
            result,
            path,
            JSON.parse(
              decrypted
            )
          );
        } catch {
          setAtPath(
            result,
            path,
            decrypted
          );
        }
      }
    }

    return JSON.stringify(
      result,
      null,
      2
    );
  }

  async function processInput() {
    setError("");
    setSuccess("");
    setOutput("");
    setProcessing(true);

    try {
      if (
        !input.trim()
      ) {
        throw new Error(
          "Input is required."
        );
      }

      if (
        !secretKey.trim()
      ) {
        throw new Error(
          "Secret key is required."
        );
      }

      /*
       * ===========================================================
       * NON-JSON
       * ===========================================================
       */
      if (!isJSON) {
        const result =
          operation ===
          "encrypt"
            ? await encryptValue(
                input
              )
            : await decryptValue(
                input
              );

        setOutput(
          result
        );

        setSuccess(
          "Input processed successfully."
        );

        return;
      }

      /*
       * ===========================================================
       * ENTIRE JSON
       * ===========================================================
       */
      if (
        scope ===
        "ENTIRE"
      ) {
        const result =
          operation ===
          "encrypt"
            ? await encryptValue(
                input
              )
            : await decryptValue(
                input
              );

        setOutput(
          result
        );

        setSuccess(
          operation ===
          "encrypt"
            ? "Entire JSON encrypted as one value."
            : "Entire encrypted value decrypted."
        );

        return;
      }

      /*
       * ===========================================================
       * SPECIFIC JSON VALUES
       * ===========================================================
       */
      if (
        scope ===
          "SPECIFIC" &&
        selectedPaths.length ===
          0
      ) {
        throw new Error(
          "Select at least one JSON value."
        );
      }

      const result =
        await processJSONValues();

      setOutput(
        result
      );

      setSuccess(
        operation ===
        "encrypt"
          ? "JSON values encrypted successfully."
          : "JSON values decrypted successfully."
      );
    } catch (
      error
    ) {
      console.error(
        error
      );

      setError(
        error?.message ||
          "Processing failed."
      );
    } finally {
      setProcessing(
        false
      );
    }
  }


  async function reverseOutput() {
    if (!output.trim()) {
      setError(
        "Output is empty."
      );
      return;
    }

    setError("");
    setSuccess("");
    setProcessing(true);

    const reverseOperation =
      operation === "encrypt"
        ? "decrypt"
        : "encrypt";

    /*
     * Reverse processing intentionally uses the
     * CURRENT AES configuration unchanged.
     * In particular, Manual IV and Ciphertext Only
     * stay Manual IV and Ciphertext Only.
     */

    try {
      /*
       * Entire scope or raw input:
       * treat Output as one value.
       */
      if (
        scope === "ENTIRE" ||
        !isJSON
      ) {
        const result =
          reverseOperation ===
          "encrypt"
            ? await encryptValue(
                output
              )
            : await decryptValue(
                output
              );

        setOutput(result);

        setSuccess(
          reverseOperation ===
            "encrypt"
            ? "Edited output encrypted successfully."
            : "Output decrypted successfully."
        );

        return;
      }

      /*
       * All / specific JSON scopes:
       * Output is expected to be a JSON/JSONC
       * structure, so reverse-process the same
       * selected paths.
       */
      let outputJSON;

      const parsedOutput =
        parseJSONInput(output);

      if (!parsedOutput.valid) {
        throw new Error(
          "Output must contain valid JSON/JSONC when using a JSON-value scope."
        );
      }

      outputJSON =
        parsedOutput.value;

      /*
       * Temporarily process the output JSON
       * using the opposite operation.
       */
      const originalScope = scope;

      const originalSelectedPaths =
        selectedPaths;

      /*
       * Build a list from the output JSON so
       * arrays/nested objects are handled using
       * the exact same path logic.
       */
      const outputPaths =
        collectJSONPaths(
          outputJSON
        );

      let pathsToProcess = [];

      if (
        originalScope ===
        "ALL_VALUES"
      ) {
        pathsToProcess =
          outputPaths
            .filter(
              (item) =>
                item.type ===
                "value"
            )
            .map(
              (item) =>
                item.path
            );
      } else {
        pathsToProcess =
          outputPaths
            .filter(
              (item) => {
                if (
                  item.type !==
                  "value"
                ) {
                  return false;
                }

                return originalSelectedPaths.some(
                  (selected) =>
                    pathMatches(
                      item.path,
                      selected
                    )
                );
              }
            )
            .map(
              (item) =>
                item.path
            );
      }

      if (
        pathsToProcess.length ===
        0
      ) {
        throw new Error(
          "No JSON values are available for reverse processing."
        );
      }

      let result =
        cloneJSON(
          outputJSON
        );

      for (
        const path of
        pathsToProcess
      ) {
        const original =
          getAtPath(
            result,
            path
          );

        if (
          original === "" ||
          original === null ||
          original === undefined
        ) {
          continue;
        }

        const textValue =
          typeof original ===
          "string"
            ? original
            : JSON.stringify(
                original
              );

        if (
          reverseOperation ===
          "encrypt"
        ) {
          const encrypted =
            await encryptValue(
              textValue
            );

          setAtPath(
            result,
            path,
            encrypted
          );
        } else {
          const decrypted =
            await decryptValue(
              textValue
            );

          try {
            setAtPath(
              result,
              path,
              JSON.parse(
                decrypted
              )
            );
          } catch {
            setAtPath(
              result,
              path,
              decrypted
            );
          }
        }
      }

      setOutput(
        JSON.stringify(
          result,
          null,
          2
        )
      );

      setSuccess(
        reverseOperation ===
          "encrypt"
          ? "Edited JSON output encrypted successfully."
          : "JSON output decrypted successfully."
      );
    } catch (reverseError) {
      console.error(
        reverseError
      );

      setError(
        reverseError?.message ||
          "Unable to reverse-process the output."
      );
    } finally {
      setProcessing(false);
    }
  }

  function togglePath(
    path
  ) {
    setSelectedPaths(
      (current) =>
        current.includes(
          path
        )
          ? current.filter(
              (item) =>
                item !==
                path
            )
          : [
              ...current,
              path,
            ]
    );
  }

  function selectAllPaths() {
    setSelectedPaths(
      jsonPaths.map(
        (item) =>
          item.path
      )
    );
  }

  function clearPaths() {
    setSelectedPaths(
      []
    );
  }

  async function copyInput() {
    if (!input) {
      return;
    }

    try {
      await navigator.clipboard.writeText(
        input
      );

      setSuccess(
        "Input copied."
      );

      setTimeout(
        () => setSuccess(""),
        1500
      );
    } catch {
      setError(
        "Unable to copy input."
      );
    }
  }

  async function copyOutput() {
    if (
      !output
    ) {
      return;
    }

    await navigator.clipboard.writeText(
      output
    );

    setSuccess(
      "Output copied."
    );

    setTimeout(
      () =>
        setSuccess(""),
      1500
    );
  }

  function clearAll() {
    setInput("");
    setOutput("");
    setError("");
    setSuccess("");
    setSelectedPaths([]);

    try {
      sessionStorage.removeItem(
        STORAGE_KEY
      );
    } catch {
      // Ignore storage errors.
    }
  }

  const requiredKeyBytes =
    KEY_BYTES[
      String(keySize)
    ];

  return (
    <div className="app">

      {/* ==========================================================
          HEADER
      ========================================================== */}

      <header className="header">

        <div>
          <h1>
            Universal AES Encryption Tool
          </h1>

          <p>
            Configurable AES
            encryption/decryption
            for raw input and
            arbitrary JSON.
          </p>
        </div>

        <span className="badge">
          Browser only
        </span>

      </header>

      {/* ==========================================================
          CONFIGURATION
      ========================================================== */}

      <section className="config-card">

        <div className="config-grid">

          <Field label="Operation">
            <select
              value={
                operation
              }
              onChange={(e) =>
                handleOperationChange(
                  e.target
                    .value
                )
              }
            >
              <option value="encrypt">
                Encrypt
              </option>

              <option value="decrypt">
                Decrypt
              </option>
            </select>
          </Field>

          <Field label="AES Key Size">
            <select
              value={
                keySize
              }
              onChange={(e) =>
                setKeySize(
                  e.target
                    .value
                )
              }
            >
              <option value="128">
                AES-128
              </option>

              <option value="192">
                AES-192
              </option>

              <option value="256">
                AES-256
              </option>
            </select>
          </Field>

          <Field label="AES Mode">
            <select
              value={mode}
              onChange={(e) =>
                handleModeChange(
                  e.target
                    .value
                )
              }
            >
              <option value="CBC">
                AES-CBC
              </option>

              <option value="ECB">
                AES-ECB
              </option>

              <option value="CFB">
                AES-CFB
              </option>

              <option value="OFB">
                AES-OFB
              </option>

              <option value="CTR">
                AES-CTR
              </option>

              <option value="GCM">
                AES-GCM
              </option>
            </select>
          </Field>

          <Field label="Padding">
            <select
              value={
                padding
              }
              disabled={
                !currentMode.supportsPadding
              }
              onChange={(e) =>
                setPadding(
                  e.target
                    .value
                )
              }
            >
              {PADDINGS.map(
                (item) => (
                  <option
                    key={
                      item.value
                    }
                    value={
                      item.value
                    }
                  >
                    {
                      item.label
                    }
                  </option>
                )
              )}
            </select>
          </Field>

          <Field
            label="Secret Key"
            hint={`Required: ${requiredKeyBytes} bytes`}
          >

            <div className="password-wrap">

              <input
                type={
                  showKey
                    ? "text"
                    : "password"
                }
                value={
                  secretKey
                }
                onChange={(e) =>
                  setSecretKey(
                    e.target
                      .value
                  )
                }
                placeholder="Enter secret key"
              />

              <button
                type="button"
                className="show-button"
                onClick={() =>
                  setShowKey(
                    (value) =>
                      !value
                  )
                }
              >
                {showKey
                  ? "Hide"
                  : "Show"}
              </button>

            </div>

          </Field>

          <Field label="Key Encoding">
            <select
              value={
                keyEncoding
              }
              onChange={(e) =>
                setKeyEncoding(
                  e.target
                    .value
                )
              }
            >
              <option value="UTF8">
                UTF-8
              </option>

              <option value="HEX">
                Hex
              </option>

              <option value="BASE64">
                Base64
              </option>
            </select>
          </Field>

          <Field label="IV Handling">
            <select
              value={
                ivHandling
              }
              disabled={
                mode ===
                "ECB"
              }
              onChange={(e) =>
                setIvHandling(
                  e.target
                    .value
                )
              }
            >
              <option value="GENERATE">
                Auto Generate
              </option>

              <option value="EXTRACT">
                Extract From Input
              </option>

              <option value="MANUAL">
                Manual IV
              </option>
            </select>
          </Field>

          <Field label="IV Size (bytes)">
            <input
              type="number"
              min="1"
              value={
                mode ===
                "ECB"
                  ? 0
                  : ivSize
              }
              disabled={
                mode ===
                "ECB"
              }
              onChange={(e) =>
                setIvSize(
                  Number(
                    e.target
                      .value
                  )
                )
              }
            />
          </Field>

          <Field label="IV / Ciphertext Layout">
            <select
              value={
                prependIv
                  ? "IV_CIPHERTEXT"
                  : "CIPHERTEXT_ONLY"
              }
              disabled={
                mode ===
                "ECB"
              }
              onChange={(e) =>
                setPrependIv(
                  e.target
                    .value ===
                    "IV_CIPHERTEXT"
                )
              }
            >
              <option value="IV_CIPHERTEXT">
                IV + Ciphertext
              </option>

              <option value="CIPHERTEXT_ONLY">
                Ciphertext Only
              </option>
            </select>
          </Field>

          {ivHandling ===
            "MANUAL" &&
            mode !==
              "ECB" && (
              <>
                <Field label="Manual IV">
                  <input
                    value={
                      manualIV
                    }
                    onChange={(e) =>
                      setManualIV(
                        e.target
                          .value
                      )
                    }
                    placeholder="Enter IV"
                  />
                </Field>

                <Field label="IV Encoding">
                  <select
                    value={
                      ivEncoding
                    }
                    onChange={(e) =>
                      setIvEncoding(
                        e.target
                          .value
                      )
                    }
                  >
                    <option value="BASE64">
                      Base64
                    </option>

                    <option value="HEX">
                      Hex
                    </option>

                    <option value="UTF8">
                      UTF-8
                    </option>
                  </select>
                </Field>
              </>
            )}

          <Field label="Input Encoding">
            <select
              value={
                inputEncoding
              }
              onChange={(e) =>
                setInputEncoding(
                  e.target
                    .value
                )
              }
            >
              <option value="BASE64">
                Base64
              </option>

              <option value="HEX">
                Hex
              </option>

              <option value="UTF8">
                UTF-8
              </option>
            </select>
          </Field>

          <Field label="Output Encoding">
            <select
              value={
                outputEncoding
              }
              onChange={(e) =>
                setOutputEncoding(
                  e.target
                    .value
                )
              }
            >
              <option value="BASE64">
                Base64
              </option>

              <option value="HEX">
                Hex
              </option>

              <option value="UTF8">
                UTF-8
              </option>
            </select>
          </Field>

        </div>

        {/* ========================================================
            JSON SCOPE
        ========================================================= */}

        <div className="scope-area">

          <div className="scope-heading">

            <div>
              <h2>
                What do you want to{" "}
                {operation ===
                "encrypt"
                  ? "encrypt"
                  : "decrypt"}
                ?
              </h2>

              <p>
                Choose how the input
                should be processed.
              </p>
            </div>

            {isJSON && (
              <span className="json-tag">
                JSON / JSONC detected
              </span>
            )}

          </div>

          <div className="scope-grid">

            <label
              className={`scope-card ${
                scope ===
                "ENTIRE"
                  ? "selected"
                  : ""
              }`}
            >

              <input
                type="radio"
                name="scope"
                checked={
                  scope ===
                  "ENTIRE"
                }
                onChange={() =>
                  setScope(
                    "ENTIRE"
                  )
                }
              />

              <div>
                <strong>
                  Entire Input / JSON
                </strong>

                <span>
                  Encrypt/decrypt the
                  complete input as one value.
                </span>
              </div>

            </label>

            <label
              className={`scope-card ${
                scope ===
                "ALL_VALUES"
                  ? "selected"
                  : ""
              } ${
                !isJSON
                  ? "disabled"
                  : ""
              }`}
            >

              <input
                type="radio"
                name="scope"
                disabled={
                  !isJSON
                }
                checked={
                  scope ===
                  "ALL_VALUES"
                }
                onChange={() =>
                  setScope(
                    "ALL_VALUES"
                  )
                }
              />

              <div>
                <strong>
                  All JSON Values
                </strong>

                <span>
                  Encrypt/decrypt every
                  primitive value separately.
                </span>
              </div>

            </label>

            <label
              className={`scope-card ${
                scope ===
                "SPECIFIC"
                  ? "selected"
                  : ""
              } ${
                !isJSON
                  ? "disabled"
                  : ""
              }`}
            >

              <input
                type="radio"
                name="scope"
                disabled={
                  !isJSON
                }
                checked={
                  scope ===
                  "SPECIFIC"
                }
                onChange={() =>
                  setScope(
                    "SPECIFIC"
                  )
                }
              />

              <div>
                <strong>
                  Specific JSON Values
                </strong>

                <span>
                  Select individual
                  fields, objects and arrays.
                </span>
              </div>

            </label>

          </div>

          {!isJSON && (
            <div className="raw-notice">
              Paste valid JSON or JSONC to
              enable JSON field selection.
            </div>
          )}

          {isJSON &&
            scope ===
              "SPECIFIC" && (
              <div className="field-selector">

                <div className="field-selector-header">

                  <div>
                    <strong>
                      JSON Values
                    </strong>

                    <span>
                      {
                        selectedPaths.length
                      }{" "}
                      selected
                    </span>
                  </div>

                  <div className="field-actions">

                    <button
                      type="button"
                      onClick={
                        selectAllPaths
                      }
                    >
                      Select All
                    </button>

                    <button
                      type="button"
                      onClick={
                        clearPaths
                      }
                    >
                      Clear
                    </button>

                  </div>

                </div>

                <div className="field-list">

                  {jsonPaths.map(
                    (item) => (
                      <label
                        key={
                          item.path
                        }
                        className={`field-row ${
                          item.type ===
                          "branch"
                            ? "branch"
                            : ""
                        }`}
                      >

                        <input
                          type="checkbox"
                          checked={selectedPaths.includes(
                            item.path
                          )}
                          onChange={() =>
                            togglePath(
                              item.path
                            )
                          }
                        />

                        <span className="field-path">
                          {
                            item.path
                          }
                        </span>

                        <span className="field-type">
                          {
                            item.type
                          }
                        </span>

                      </label>
                    )
                  )}

                </div>

              </div>
            )}

        </div>

        <div className="config-footer">

          <strong>
            AES-{keySize}-{mode}
          </strong>

          <span>
            Padding:{" "}
            <b>
              {currentMode.supportsPadding
                ? padding
                : "Not Applicable"}
            </b>
          </span>

          <span>
            IV:{" "}
            <b>
              {mode ===
              "ECB"
                ? "None"
                : `${ivSize} bytes`}
            </b>
          </span>

          <span>
            Layout:{" "}
            <b>
              {mode ===
              "ECB"
                ? "N/A"
                : prependIv
                ? "IV + Ciphertext"
                : "Ciphertext Only"}
            </b>
          </span>

        </div>

      </section>

      {/* ==========================================================
          WORKSPACE
      ========================================================== */}

      <main className="workspace">

        <section className="panel">

          <div className="panel-header">

            <div>
              <h2>
                Input
              </h2>

              {isJSON ? (
                <span className="small-tag">
                  JSON / JSONC
                </span>
              ) : (
                <span className="small-tag raw">
                  RAW
                </span>
              )}
            </div>

            <div className="panel-actions">

              <button
                type="button"
                disabled={!input}
                onClick={
                  copyInput
                }
              >
                Copy
              </button>

              <button
                type="button"
                onClick={
                  clearAll
                }
              >
                Clear
              </button>

            </div>

          </div>

          <textarea
            className="payload"
            value={
              input
            }
            onChange={(e) =>
              handleInputChange(
                e.target
                  .value
              )
            }
            placeholder="Paste JSON, JSONC, encrypted Base64, plaintext or raw text..."
            spellCheck="false"
          />

        </section>

        <section className="processing-panel">

          <h2>
            Processing
          </h2>

          <div className="processing-info">

            <InfoRow
              label="Operation"
              value={
                operation ===
                "encrypt"
                  ? "Encryption"
                  : "Decryption"
              }
            />

            <InfoRow
              label="AES"
              value={`AES-${keySize}`}
            />

            <InfoRow
              label="Mode"
              value={mode}
            />

            <InfoRow
              label="Padding"
              value={
                currentMode.supportsPadding
                  ? padding
                  : "N/A"
              }
            />

            <InfoRow
              label="Input"
              value={
                isJSON
                  ? "JSON"
                  : "Raw"
              }
            />

            <InfoRow
              label="Scope"
              value={
                scope ===
                "ENTIRE"
                  ? "Entire"
                  : scope ===
                    "ALL_VALUES"
                  ? "All values"
                  : `${selectedPaths.length} selected`
              }
            />

          </div>

          <button
            type="button"
            className="process-button"
            disabled={
              processing
            }
            onClick={
              processInput
            }
          >
            {processing
              ? "Processing..."
              : operation ===
                "encrypt"
              ? "Encrypt"
              : "Decrypt"}
          </button>

          {error && (
            <div className="error-box">
              {error}
            </div>
          )}

          {success && (
            <div className="success-box">
              {success}
            </div>
          )}

        </section>

        <section className="panel">

          <div className="panel-header">

            <h2>
              Output
            </h2>

            <div className="panel-actions">

              <button
                type="button"
                disabled={
                  !output
                }
                onClick={
                  copyOutput
                }
              >
                Copy
              </button>

              <button
                type="button"
                className="reverse-button"
                disabled={
                  !output ||
                  processing
                }
                onClick={
                  reverseOutput
                }
              >
                {operation ===
                "decrypt"
                  ? "Encrypt Output"
                  : "Decrypt Output"}
              </button>

            </div>

          </div>

          <textarea
            className="payload output"
            value={
              output
            }
            onChange={(e) => {
              setOutput(
                e.target.value
              );
              setError("");
              setSuccess("");
            }}
            placeholder="Processed result will appear here..."
            spellCheck="false"
          />

        </section>

      </main>

    </div>
  );
}

/* =========================================================================
   UI HELPERS
========================================================================= */

function Field({
  label,
  hint,
  children,
}) {
  return (
    <div className="field">

      <label>
        {label}
      </label>

      {children}

      {hint && (
        <small>
          {hint}
        </small>
      )}

    </div>
  );
}

function InfoRow({
  label,
  value,
}) {
  return (
    <div>
      <span>
        {label}
      </span>

      <strong>
        {value}
      </strong>
    </div>
  );
}

/* =========================================================================
   START
========================================================================= */

createRoot(
  document.getElementById(
    "root"
  )
).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);