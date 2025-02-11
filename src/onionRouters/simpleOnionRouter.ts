import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT, BASE_USER_PORT } from "../config";
import { 
  generateRsaKeyPair, 
  exportPubKey, 
  exportPrvKey, 
  rsaDecrypt, 
  importSymKey, 
  symDecrypt 
} from "../crypto";
import axios from "axios";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());

  const { publicKey, privateKey } = await generateRsaKeyPair();
  const pubKeyStr = await exportPubKey(publicKey);

  // Register to the registry
  await axios.post(`http://localhost:${REGISTRY_PORT}/registerNode`, {
    nodeId,
    pubKey: pubKeyStr
  });

  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  onionRouter.get("/getPrivateKey", async (req, res) => {
    const prvKeyStr = await exportPrvKey(privateKey);
    res.json({ result: prvKeyStr });
  });

  onionRouter.post("/message", async (req, res) => {
    try {
      const { message } = req.body;

      // 10 chars = port, suivis de 4 chars = taille de la clé RSA
      const destinationPort = parseInt(message.substring(0, 10));
      const keyLength = parseInt(message.substring(10, 14));

      const encryptedKeyStart = 14;
      const encryptedKeyEnd = 14 + keyLength;
      const encryptedKey = message.substring(encryptedKeyStart, encryptedKeyEnd);

      const encryptedData = message.substring(encryptedKeyEnd);

      const symKeyStr = await rsaDecrypt(encryptedKey, privateKey);
      const symKey = await importSymKey(symKeyStr);
      const decryptedData = await symDecrypt(symKey, encryptedData);

      lastReceivedEncryptedMessage = message;
      lastReceivedDecryptedMessage = decryptedData;
      lastMessageDestination = destinationPort;

      console.log(`Node ${nodeId} forwarding to ${destinationPort}`);

      await axios.post(`http://localhost:${destinationPort}/message`, {
        message: decryptedData
      });

      res.send("success");
    } catch (error) {
      console.error(`Node ${nodeId} error:`, error);
      res.status(500).send((error as Error).message);
    }
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(`Onion router ${nodeId} is listening on port ${BASE_ONION_ROUTER_PORT + nodeId}`);
  });

  return server;
}
