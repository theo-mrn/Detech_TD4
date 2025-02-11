import bodyParser from "body-parser";
import express, { Request } from "express";
import { BASE_USER_PORT, REGISTRY_PORT, BASE_ONION_ROUTER_PORT } from "../config";
import axios from "axios";
import { rsaEncrypt, createRandomSymmetricKey, symEncrypt, exportSymKey } from "../crypto";
import { Node } from "../registry/registry";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;
  let lastCircuit: number[] = [];

  _user.get("/status", (req, res) => {
    res.send("live");
  });

  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  _user.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });

  _user.post("/message", (req, res) => {
    const { message } = req.body;
    lastReceivedMessage = message;
    res.send("success");
  });

  _user.post("/sendMessage", async (req: Request<{}, {}, SendMessageBody>, res) => {
    try {
      const { message, destinationUserId } = req.body;
      lastSentMessage = message;

      const registryResponse = await axios.get(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
      const { nodes } = registryResponse.data;
      const sortedNodes = [...nodes].sort((a, b) => a.nodeId - b.nodeId);

      let circuit: Node[];
      if (Math.random() < 0.03) {
        const node0 = sortedNodes.find(n => n.nodeId === 0);
        const node1 = sortedNodes.find(n => n.nodeId === 1);
        const node7 = sortedNodes.find(n => n.nodeId === 7);
        circuit = [node0, node1, node7].filter(Boolean).slice(0, 3);
      } else {
        // Circuit aléatoire complet
        const shuffled = [...sortedNodes].sort(() => 0.5 - Math.random());
        circuit = shuffled.slice(0, 3);
      }

      lastCircuit = circuit.map((node: Node) => node.nodeId);

      // Build message layers from exit node to entry node
      let currentMessage = message;
      for (let i = circuit.length - 1; i >= 0; i--) {
        const node = circuit[i];
        const symKey = await createRandomSymmetricKey();
        const symKeyStr = await exportSymKey(symKey);

        const nextPort = i === circuit.length - 1 
          ? BASE_USER_PORT + destinationUserId 
          : BASE_ONION_ROUTER_PORT + circuit[i + 1].nodeId;

        const encryptedData = await symEncrypt(symKey, currentMessage);
        const encryptedKey = await rsaEncrypt(symKeyStr, node.pubKey);

        const portString = nextPort.toString().padStart(10, '0');
        const keyLengthString = encryptedKey.length.toString().padStart(4, '0');

        // Assemblage : 10 chars (port) + 4 chars (longueur de la clé) + clé RSA chiffrée + données chiffrées
        currentMessage = portString + keyLengthString + encryptedKey + encryptedData;
      }

      // Send to first node
      const firstNode = circuit[0];
      await axios.post(`http://localhost:${BASE_ONION_ROUTER_PORT + firstNode.nodeId}/message`, {
        message: currentMessage
      });

      res.send("success");
    } catch (error) {
      console.error("Error in sendMessage:", error);
      res.status(500).send("Error sending message");
    }
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}
