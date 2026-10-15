import { connect } from 'cloudflare:sockets';

let defaultUUID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

export default {
  async fetch(request, env, ctx) {
    try {
      const upgradeHeader = request.headers.get("Upgrade");
      if (upgradeHeader === "websocket") {
        return await vlessOverWSHandler(request);
      }
      return new Response("King Proxy is Running!", { status: 200 });
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  }
};

async function vlessOverWSHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);
  let remoteSocketWapper = { value: null };

  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk) {
      if (remoteSocketWapper.value) {
        const writer = remoteSocketWapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }
      const { hasError, message, portRemote = 443, addressRemote = '', rawDataIndex, vlessVersion = new Uint8Array([0, 0]) } = processVlessHeader(chunk);
      if (hasError) throw new Error(message);
      
      const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
      const rawClientData = chunk.slice(rawDataIndex);
      handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader);
    },
  })).catch(() => {});

  return new Response(null, { status: 101, webSocket: client });
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader) {
  const tcpSocket = connect({ hostname: addressRemote, port: portRemote });
  remoteSocket.value = tcpSocket;
  const writer = tcpSocket.writable.getWriter();
  await writer.write(rawClientData);
  writer.releaseLock();
  
  remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader);
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader) {
  let readableStreamCancel = false;
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => {
        if (!readableStreamCancel) controller.enqueue(event.data);
      });
      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        if (!readableStreamCancel) controller.close();
      });
    },
    cancel() {
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    }
  });
}

function processVlessHeader(vlessBuffer) {
  if (vlessBuffer.byteLength < 24) return { hasError: true, message: 'invalid data' };
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  return { hasError: false, addressRemote: '127.0.0.1', portRemote: 443, rawDataIndex: 24, vlessVersion: version };
}

async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader) {
  let vlessHeader = vlessResponseHeader;
  await remoteSocket.readable.pipeTo(new WritableStream({
    async write(chunk) {
      if (webSocket.readyState !== 1) return;
      if (vlessHeader) {
        webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
        vlessHeader = null;
      } else {
        webSocket.send(chunk);
      }
    },
  })).catch(() => { safeCloseWebSocket(webSocket); });
}

function safeCloseWebSocket(socket) {
  try { if (socket.readyState === 1 || socket.readyState === 2) socket.close(); } catch (e) {}
}
