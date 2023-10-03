const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const readline = require('readline-sync');

const language = process.env.LANGUAGE || 'en'; //de

const messages = {
  en: {
    keyPairGenerated: '4096-bit key pair has been generated and saved.',
    fileEncrypted: 'File has been encrypted and saved as',
    fileDecrypted: 'File has been decrypted and saved as',
    enterText: 'Enter text to encrypt:',
    encryptedText: 'Encrypted text:',
    enterEncryptedText: 'Enter text to decrypt:',
    decryptedText: 'Decrypted text:',
    keyIdInfo: 'The Key ID is for internal identification purposes and is not needed for regular use. DO NOT RENAME, EDIT, OR DELETE THIS FILE!',
    selectKey: 'Select a key pair to use:',
    addKeyPair: 'Add an existing key pair:',
    enterPublicKeyPath: 'Enter the path to the public key file:',
    enterPrivateKeyPath: 'Enter the path to the private key file:',
    keyPairAdded: 'Key pair has been added.',
  },
  de: {
    keyPairGenerated: '4096-Bit-Schlüsselpaar wurde erstellt und gespeichert.',
    fileEncrypted: 'Datei wurde verschlüsselt und gespeichert als',
    fileDecrypted: 'Datei wurde entschlüsselt und gespeichert als',
    enterText: 'Gib den zu verschlüsselnden Text ein:',
    encryptedText: 'Verschlüsselter Text:',
    enterEncryptedText: 'Gib den zu entschlüsselnden Text im Hex-Format ein:',
    decryptedText: 'Entschlüsselter Text:',
    keyIdInfo: 'Die Key-ID dient internen Identifikationszwecken und wird für die normale Verwendung nicht benötigt. DIESE DATEI DARF NICHT UMBENANNT, BEARBEITET ODER GELÖSCHT WERDEN!',
    selectKey: 'Wähle ein Schlüsselpaar aus:',
    addKeyPair: 'Füge ein bestehendes Schlüsselpaar hinzu:',
    enterPublicKeyPath: 'Gib den Pfad zur öffentlichen Schlüsseldatei ein:',
    enterPrivateKeyPath: 'Gib den Pfad zur privaten Schlüsseldatei ein:',
    keyPairAdded: 'Schlüsselpaar wurde hinzugefügt.',

	// TODO: Swedish, Russian and Chinese
  }
};

function t(key) {
  return messages[language][key];
}

function listKeys() {
  const keyInfoFiles = findKeyInfoFiles(__dirname);
  keyInfoFiles.forEach((keyInfoFile, index) => {
    const keyInfo = fs.readFileSync(keyInfoFile, 'utf-8');
    const keyIdMatch = keyInfo.match(/Key ID: (.+)/);
    if (keyIdMatch) {
      console.log(`${index + 1}. Key ID: ${keyIdMatch[1]}`);
    }
  });
  return keyInfoFiles;
}

function findKeyInfoFiles(directory) {
  const keyInfoFiles = [];
  const entries = fs.readdirSync(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      keyInfoFiles.push(...findKeyInfoFiles(path.join(directory, entry.name)));
    } else if (entry.isFile() && entry.name === 'key_info.txt') {
      keyInfoFiles.push(path.join(directory, entry.name));
    }
  }
  return keyInfoFiles;
}

function selectKeyPair() {
  const keyInfoFiles = listKeys();
  const keyIndex = parseInt(readline.question(`${t('selectKey')} `)) - 1;
  if (keyIndex >= 0 && keyIndex < keyInfoFiles.length) {
    const selectedKeyInfo = fs.readFileSync(keyInfoFiles[keyIndex], 'utf-8');
    const keyIdMatch = selectedKeyInfo.match(/Key ID: (.+)/);
    if (keyIdMatch) {
      return keyIdMatch[1];
    }
  }
  console.error('Invalid key selection.');
  process.exit(1);
}

function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });

  const id = crypto.randomBytes(16).toString('hex');
  const keyDir = path.join(__dirname, id);
  fs.mkdirSync(keyDir);
  fs.writeFileSync(path.join(keyDir, 'public_key.pem'), publicKey);
  fs.writeFileSync(path.join(keyDir, 'private_key.pem'), privateKey);
  fs.writeFileSync(path.join(keyDir, 'key_info.txt'), `Key ID: ${id}\n${t('keyIdInfo')}\n`);
  console.log(t('keyPairGenerated'));
  console.log(`Key ID: ${id}`);
}

function encryptFile(inputFile, outputFile, publicKey) {
  const plaintextBuffer = fs.readFileSync(inputFile);
  const encryptedBuffer = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, plaintextBuffer);
  fs.writeFileSync(outputFile, encryptedBuffer);
  console.log(`${t('fileEncrypted')} ${outputFile}`);
}

function decryptFile(inputFile, outputFile, privateKey) {
  const encryptedBuffer = fs.readFileSync(inputFile);
  const decryptedBuffer = crypto.privateDecrypt({ key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, encryptedBuffer);
  fs.writeFileSync(outputFile, decryptedBuffer);
  console.log(`${t('fileDecrypted')} ${outputFile}`);
}

function encryptText(plaintext, publicKey) {
  const encryptedBuffer = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, Buffer.from(plaintext, 'utf-8'));
  return encryptedBuffer.toString('hex');
}

function decryptText(ciphertext, privateKey) {
  const encryptedBuffer = Buffer.from(ciphertext, 'hex');
  const decryptedBuffer = crypto.privateDecrypt({ key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, encryptedBuffer);
  return decryptedBuffer.toString('utf-8');
}

function addKeyPair() {
  const publicKeyPath = readline.question(`${t('enterPublicKeyPath')} `);
  const privateKeyPath = readline.question(`${t('enterPrivateKeyPath')} `);

  if (!fs.existsSync(publicKeyPath) || !fs.existsSync(privateKeyPath)) {
    console.error('Invalid key files.');
    process.exit(1);
  }

  const id = crypto.randomBytes(16).toString('hex');
  const keyDir = path.join(__dirname, id);
  fs.mkdirSync(keyDir);

  const publicKey = fs.readFileSync(publicKeyPath, 'utf-8');
  const privateKey = fs.readFileSync(privateKeyPath, 'utf-8');

  fs.writeFileSync(path.join(keyDir, 'public_key.pem'), publicKey);
  fs.writeFileSync(path.join(keyDir, 'private_key.pem'), privateKey);
  fs.writeFileSync(path.join(keyDir, 'key_info.txt'), `Key ID: ${id}\n${t('keyIdInfo')}\n`);
  console.log(t('keyPairAdded'));
  console.log(`Key ID: ${id}`);
}

function printUsage() {
  console.log(t('Usage:'));
  console.log('  node script.js generate-key-pair   # Generate key pair');
  console.log('  node script.js list-keys          # List available key pairs');
  console.log('  node script.js encrypt-file -i input.txt -o output.enc   # Encrypt file');
  console.log('  node script.js decrypt-file -i input.enc -o output.txt   # Decrypt file');
  console.log('  node script.js encrypt-text -t "My secret text"   # Encrypt text');
  console.log('  node script.js decrypt-text -t "Encrypted text"   # Decrypt text');
  console.log('  node script.js add-key-pair        # Add an existing key pair');
}

const args = process.argv.slice(2);
if (args.length === 0) {
  printUsage();
  process.exit(1);
}

const action = args[0];
if (action === 'generate-key-pair') {
  generateKeyPair();
} else if (action === 'list-keys') {
  listKeys();
} else if (action === 'encrypt-file' || action === 'decrypt-file') {
  const keyId = selectKeyPair();
  const publicKey = fs.readFileSync(path.join(__dirname, keyId, 'public_key.pem'), 'utf-8');
  const privateKey = fs.readFileSync(path.join(__dirname, keyId, 'private_key.pem'), 'utf-8');

  const inputIndex = args.indexOf('-i');
  const outputIndex = args.indexOf('-o');
  if (inputIndex === -1 || outputIndex === -1 || inputIndex + 1 >= args.length || outputIndex + 1 >= args.length) {
    console.error('Invalid usage. Please specify input and output files.');
    printUsage();
    process.exit(1);
  }
  const inputFile = args[inputIndex + 1];
  const outputFile = args[outputIndex + 1];
  if (action === 'encrypt-file') {
    encryptFile(inputFile, outputFile, publicKey);
  } else {
    decryptFile(inputFile, outputFile, privateKey);
  }
} else if (action === 'encrypt-text' || action === 'decrypt-text') {
  const keyId = selectKeyPair();
  const publicKey = fs.readFileSync(path.join(__dirname, keyId, 'public_key.pem'), 'utf-8');
  const privateKey = fs.readFileSync(path.join(__dirname, keyId, 'private_key.pem'), 'utf-8');

  const textIndex = args.indexOf('-t');
  if (textIndex === -1 || textIndex + 1 >= args.length) {
    console.error('Invalid usage. Please specify the text.');
    printUsage();
    process.exit(1);
  }
  const text = args[textIndex + 1];
  if (action === 'encrypt-text') {
    const encryptedText = encryptText(text, publicKey);
    console.log(t('encryptedText'));
    console.log(encryptedText);
  } else {
    const decryptedText = decryptText(text, privateKey);
    console.log(t('decryptedText'));
    console.log(decryptedText);
  }
} else if (action === 'add-key-pair') {
  addKeyPair();
} else {
  console.error('Invalid action. Please use one of the following actions: generate-key-pair, list-keys, encrypt-file, decrypt-file, encrypt-text, decrypt-text, add-key-pair.');
  printUsage();
  process.exit(1);
}
