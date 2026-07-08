class PeerConnectionManager {
  constructor(options) {
    this.cw = new CryptoWrapper(sodium);
    // init with default options if needed
    options ??= this.getDefaultOptions();    
    // the version of the whole program
    this.version = options.USERDATA.version;
    // list of the actual connections, and attributes about them
    // stored in subobjects, such as .webrtc, .iroh, etc.
    // This contains alive and dead connections
    this.connections = {};
    // the list of connection types to add
    this.connectionModes = options.type;
    // the actual local peer objects, such as the PeerJS Peer object
    // or Iroh peer object
    this.peer = {};
    // this is the identity keypair used for this peer for all crypto operations
    this.identityKeypair = options.USERDATA.IDENTITY_KEY;
    this.cw.addIdentityKeypair(this.identityKeypair);
    // this is the id for the peer, which is also encoding the public key 
    // so that authentication is easier
    this.id = options.USERDATA.PEER_ID ?? this.cw.newID(this.identityKeypair.publicKey)
    console.log(this.id)
    if (this.connectionModes.includes("webrtc")) {
      this.initWebRTC(options.USERDATA)
    }
    this.handlers = this.getDefaultHandlers();
  }

  // returns defoult options to use with the Peer Connection Manager
  // it's an object, with the .type, and .USERDATA fields
  getDefaultOptions() {
    return {
      type: ["webrtc"],
      USERDATA: this.genUserData()
    }
  }

  //generates the default user data format
  genUserData() {
    return {
      "VERSION": "1.0",
      "IDENTITY_KEY": this.cw.newIdentityKeypair(),
      "webrtc": {
        "known_users": {}
      }
    }
  }
  // initializes the manager with WebRTC using an Options object
  // Sets up the .connections.webrtc object
  // runs init scripts for connecting to every peer
  // creates local peer object so that it can do things
  initWebRTC(userdata) {
    this.connections = {};
    this.peer.webrtc = new Peer(this.id, userdata.options)
    // If you have weird issues, this may be a pass by reference not value,
    // which could mess things up
    this.connections.known_users = userdata.webrtc.known_users;
    this.addWebRTCPeerListeners();
    this.findWebRTCPeers();
  }

  // this returns the default handlers for connections.
  // It is an object of the following form:
  // {'messageType': (peerId, req) => {}}
  getDefaultHandlers() {
    return {
      'handshake': (peerId, req) => {
        this.handleHandshake(peerId, req);
      },
      'ping': (peerId, req) => {
        console.log('got ping from', peerId);
      }
    }
  }

  handleHandshake(peerId, req) {
    let connectionTime = Date.now();
    // let connectionTime =  Math.floor(Date.now() / 1000 * 2);
    let stage = this.connections[peerId].webrtc.handshakeStage;
    if (stage == 1) {
      // Phase 1, client B (receiver)
      //  - verify signed keypair nonce timestamp with the identity key
      let verified = this.cw.verifySignature(req.data.signedKeypair,
                                             this.cw.hash(JSON.stringify(req.data.combinedKeypair)),
                                             this.cw.getPubkeyFromId(peerId));
      if (!verified && connectionTime - req.data.combinedKeypair.connectionTime < 2000 /* 2sec difference allowed*/) {
        // BAD!!!
        this.connections[peerId].connection.close();
        console.log("signature doesn't match for peer",peerId)
        alert("signature doesn't match for peer "+peerId)
        this.connections[peerId].webrtc.handshakeStage = -1;
        return;
      }
      console.log("verified: ",verified);
      // ourKeypair
      let theirChallenge = req.data.challenge;
      let theirPubkey = req.data.combinedKeypair.pubkey;
      let ourKeypair = this.connections[peerId].webrtc.ourKeypair;
      let nonce = this.cw.b64RandomBytes(64);

      this.connections[peerId].webrtc.handshake.theirChallenge = theirChallenge;

      this.connections[peerId].webrtc.theirPublicKey = theirPubkey;
      let sharedKey = this.cw.getSharedKey(ourKeypair.privateKey, theirPubkey);
      this.connections[peerId].webrtc.sharedKey = sharedKey;
      // this.cw.getSharedKey(ourKeypair.privateKey, theirPubkey);
      //  - sign challenge with ephemeral keypair
      //   - this ensures that keypair is known
      let signedChallenge = this.cw.encryptMessage(theirChallenge, sharedKey);
      // good news: we've already initialized most of it, now just to add the missing data
      //  - sign (ephemeral keypair + nonce + timestamp) with identity keypair to establish identity
      //   - this prevents replay attacks
      let combinedKeypair = { pubkey: ourKeypair.publicKey, nonce, connectionTime };
      let signedKeypair = this.cw.signMessage(this.cw.hash(JSON.stringify(combinedKeypair)));
      //  - generate random challenge
      let challenge = this.cw.b64RandomBytes(64);
      this.connections[peerId].webrtc.handshake.challenge = challenge;
      // Phase 2, client B
      //  - send challenge response
      let response = {
        type: "handshake",
        status: {
          code: 100,
          message: "continuing to phase 2",
        },
        data: {
          //  - send new challenge
          challenge,
          signedChallenge,
          signedKeypair,
          //  - send signed ephemeral keypair, identity pubkey, and version
          combinedKeypair,
        }
      }
      this.connections[peerId].webrtc.handshakeStage = 3;
      this.sendPacket(response,peerId)
    } else if (stage == 2) {
      this.connections[peerId].webrtc.handshakeStage = 4;
      // Phase 2, client A
      //  - verify signed keypair nonce timestamp with the identity key
      let verified = this.cw.verifySignature(req.data.signedKeypair,
                                             this.cw.hash(JSON.stringify(req.data.combinedKeypair)),
                                             this.cw.getPubkeyFromId(peerId));
      console.log("verified stage 2:",verified)
      // console.log("their data", this.connections[peerId].webrtc);
      if (!verified && connectionTime - req.data.combinedKeypair.connectionTime < 2000 /* 2sec difference allowed*/) {
        // BAD!!!
        this.connections[peerId].connection.close();
        console.log("signature doesn't match for peer",peerId)
        alert("signature doesn't match for peer "+peerId)
        this.connections[peerId].webrtc.handshakeStage = -1;
        return;
      }
      let ourKeypair = this.connections[peerId].webrtc.ourKeypair;
      let theirPubkey = req.data.combinedKeypair.pubkey;
      this.connections[peerId].webrtc.theirPublicKey = theirPubkey;
      let sharedKey = this.cw.getSharedKey(ourKeypair.privateKey, theirPubkey);
      this.connections[peerId].webrtc.sharedKey = sharedKey;
      this.connections[peerId].webrtc.handshake.theirChallenge = req.data.challenge;
      //  - verify challenge response
      let challengeVerification = this.cw.decryptMessage(req.data.signedChallenge, sharedKey)
                                  === this.connections[peerId].webrtc.handshake.challenge;
      // let challengeVerification = this.cw.verifySignature(req.data.signedChallenge,
      //                                       this.connections[peerId].webrtc.handshake.challenge,
      //                                       this.cw.getPubkeyFromId(peerId));
      //  - sign new challenge with ephemeral keypair
      let signedChallenge = this.cw.encryptMessage(req.data.challenge, sharedKey);


      let response = {
        type: "handshake",
        status: {
          code: 100,
          message: "continuing to phase 3",
        },
        data: {
          //  - send challenge response
          signedChallenge,
        }
      }
      this.sendPacket(response,peerId);

    } else  if (stage == 3) {
      // console.log("their peer info:",this.connections[peerId].webrtc)
      // Phase 3, client B
      //  - verify challenge response
      let ourKeypair = this.connections[peerId].webrtc.ourKeypair;
      let theirPubkey = this.connections[peerId].webrtc.theirPublicKey;
      let sharedKey = this.cw.getSharedKey(ourKeypair.privateKey, theirPubkey);
      let challengeVerification = this.cw.decryptMessage(req.data.signedChallenge, sharedKey)
                                  === this.connections[peerId].webrtc.handshake.challenge;
      //  - send "handshake finished" (signed)
      let response = {
        type: "handshake",
        status: {
          code: 200,
          message: "Connection open and ready",
        },
        data: { isFinished: true }
      }
      //  - mark connection as open and alive
      this.connections[peerId].webrtc.open = true;
      this.sendPacket(response,peerId);

    } else if (stage == 4) {
      if (!req.data.isFinished) {
        console.log("something went wrong")
        return;
      }
      this.connections[peerId].webrtc.open = true;
      console.log("handshake finished")
    }

    // Phase 3, client A
    //  - receive "handshake finished" (signed)
    //  - mark connection as open and alive

  }
  // this runs the specified handler with the inputs
  runHandler(type, peerId, req) {
    // checks to see if there is a callback that we stored from the message
    if (req.returnCallback && this.connections[peerId].callbacks[req.returnCallback]) {
      // run the callback
      this.connections[peerId].callbacks[req.returnCallback](req);
      // remove the callback
      delete this.connections[peerId].callbacks[req.returnCallback];
    }
    else if (this.handlers[type]) {
      this.handlers[type](peerId, req);
    } else {
      console.log("no handler for",type)

    }

  }


  // this searches all known webrtc peers, and tries to connect to them
  // It searches .connections.webrtc, which is an object,
  // where the key is the id, and the value contains the following:
  //  - the connection object (if alive)
  //  - whether or not the connection is alive or dead
  //  - last seen time (if dead)
  //  - their public key in an easier to see format
  //  - other metadata
  findWebRTCPeers() {
    Object.keys(this.connections.known_users).forEach((peerId) => {
      this.addConnection(peerId, {webrtc: true});
    })
  }

  // like sendDirectMessage, but instead sends a packet directly to the peer
  // via every available method. The packet is just raw data in whatever
  // form is specified by `packet`. This has no protections, handlers, or
  // anything.
  // Use with caution!
  sendPacket(packet, peerId) {
    // .alive means the handshake has finished as well
    if (this.connections.known_users[peerId].isAlive) {
      this.connections[peerId].webrtc.connection.send(serialize(packet));
    }
  }

  // this connects with the peer and does the 3-step handshake
  // tries to add the peerId as a connection in every connection type available
  // this is copied from the code from clientX
  // Connection handshake protocol:
  // Phase 1, client A (initiator)
  //  - connect to other peer
  //  - create ephemeral asymmetric keypair
  //  - sign (ephemeral keypair + nonce + timestamp) with identity keypair to establish identity
  //   - this prevents replay attacks
  //  - generate random challenge (random string)
  //  - send signed ephemeral keypair, identity pubkey, and version
  // Phase 1, client B (receiver)
  //  - verify signed keypair nonce timestamp with the identity key
  //  - connect to other peer
  //  - create ephemeral asymmetric keypair
  //  - sign (ephemeral keypair + nonce + timestamp) with identity keypair to establish identity
  //   - this prevents replay attacks
  //  - sign challenge with ephemeral keypair
  //   - this ensures that keypair is known
  //  - generate random challenge
  // Phase 2, client B
  //  - send challenge response
  //  - send new challenge
  //  - send signed ephemeral keypair, identity pubkey, and version
  // Phase 2, client A
  //  - verify signed keypair nonce timestamp with the identity key
  //  - verify challenge response
  //  - sign new challenge with ephemeral keypair
  //  - send challenge response
  // Phase 3, client B
  //  - verify challenge response
  //  - send "handshake finished" (signed)
  //  - mark connection as open and alive
  // Phase 3, client A
  //  - receive "handshake finished" (signed)
  //  - mark connection as open and alive
  addConnection(peerId, types /* {webrtc:bool, iroh: bool}*/, options /* options for connection */, dataConnection /* data connection object for webrtc*/) {
    // there are two different codepaths
    // When A connects to B, A is the initiator, B is not, since B is handling
    // the connection request, and A is sending it
    
    let isInitiator = false;
    if (!dataConnection) {
      isInitiator = true;
      // connect
      // TODO: Make this generic
      if (types.webrtc) {
        dataConnection = this.peer.webrtc.connect(peerId, options);
      }
      this.connections.known_users[peerId] = {
        lastConnected: 0,
        isAlive: false,
        isTrusted: false,
        pubkey: null,
      }
    }

    // connection has been established, now we will initialize the object
    // in the code
    
    let firstHandshakeAckRequest = null;

    //  - connect to other peer
    let ourKeypair = this.cw.genKeypair();
    // nonce used for signing to establish identity
    let nonce = this.cw.b64RandomBytes(64);
    // challenge to prove their pubkey
    //  - generate random challenge (random string)
    let challenge = this.cw.b64RandomBytes(64);
    // Phase 1, client A (initiator)
    //  - sign (ephemeral keypair + nonce + timestamp) with identity keypair to establish identity
    //   - this prevents replay attacks
    let connectionTime =  Date.now();
    let combinedKeypair = { pubkey: ourKeypair.publicKey, nonce, connectionTime };
    let signedKeypair = this.cw.signMessage(this.cw.hash(JSON.stringify(combinedKeypair)));
    this.connections[peerId] ??= {};
    this.connections[peerId].webrtc = {
      connection: dataConnection,
      // we change the stage number so that we can use it to handle the handshake
      // requests elegantly -- if it's even, it's initator, if odd, it's not
      handshakeStage: isInitiator ? 2 : 1,
      initiatedConnection: false,
      theirPublicKey: null,
      theirIdentityKey: this.cw.getPubkeyFromId(peerId),
      //  - create ephemeral asymmetric keypair
      ourKeypair,
      // date is with reduced precision (rounded down to 2 seconds)
      //                                       ms   sec
      connectionTime,
      open: false,
      handshake: {
        nonce,
        challenge,
        theirChallenge: null,
      }
    }
    //  - send signed ephemeral keypair, identity pubkey, and version
    firstHandshakeAckRequest = {
      type: "handshake",
      status: {
        code: 100,
        message: "beginning first handshake phase"
      },
      data: {
        signedKeypair,
        combinedKeypair,
        identityKey: this.cw.getIdentityKey(),
        challenge,
        version: this.version, 
      }
    }
    firstHandshakeAckRequest = serialize(firstHandshakeAckRequest);

    // add the listeners
    
    this.addWebRTCListeners(peerId,dataConnection, isInitiator ? firstHandshakeAckRequest: null);
   

  }
  addWebRTCPeerListeners() {
    this.peer.webrtc.on('open', () => {
      this.peer.isWebRTCOpen = true;
      console.log("peer open: ", this.id)
      //this.addConnection(this.peer.id);
      this.findWebRTCPeers();
    });
    this.peer.webrtc.on('disconnected', () => {
      this.isPeerOpen = false;
    });
    this.peer.webrtc.on('connection', (dataConnection) => {
      this.addConnection(dataConnection.peer, {webrtc: true}, {}, dataConnection);
    });
    this.peer.webrtc.on('error', (err) => {
      //console.log('error:', err);
      console.log("error: ",err.type);

      if (err.type == "peer-unavailable") {
        console.log(err.toString())
        // let id = err.toString().match(/Could not connect to peer (.*)/)[1];
        // console.log(id);
        //TODO: add clean option, then do the deleting of unessary connections
        // delete this.connections[id]
      }

    });
    this.peer.webrtc.on('close', () => {
      this.isPeerOpen = false;
    });
  }

  addWebRTCListeners(peerId,dataConnection, firstHandshakeAckRequest) {
    console.log("adding listeners for ",this.id)
    
    dataConnection.on('open', () => {
      console.log("Connection Opened");
      this.connections.known_users[peerId] = {
        lastConnected: Date.now(),
        isAlive: true,
        isTrusted: false,
        identityKey: this.cw.getPubkeyFromId(peerId),
      }

      // on connection open, send data
      if (firstHandshakeAckRequest != null) {
        dataConnection.send(firstHandshakeAckRequest);
      }

    });
    dataConnection.on('data', (data) => {
      this.handleIncomingData(peerId, data);
    });
    dataConnection.on('close', () => {
      this.connections[peerId].webrtc.open = false;
      console.log("closing")
    });
  }

  handleIncomingData(peerId, data) {
    data = deserialize(data);
    console.log("got data from",peerId,"data:",data)
    this.runHandler(data.type, peerId, data);
  }


  // tries to disconnect from peerId in every available mode
  removeConnection(peerId) {
    // sends message to the peer
    sendDirectMessage(new Message({type: "disconnect"}, "connection-update"), peerId);
    this.connections[peerId].webrtc.connection.close();
    this.connections.known_users[peerId].isAlive = false;
  }

  // lists all connected peers
  listConnections(peerId) {
    let out = [];
    for (let peerId in this.connections.known_users) {
      if (this.connections.known_users[peerId].isAlive) {
        out.push(peerId);
      }
    }
  }

  // sends a Message to every connected peer
  sendMessage(Message) {
    for (let peerId in this.connections.known_users) {
    // Object.keys(this.connections).forEach(async (peerId) => {
      this.sendDirectMessage(Message, peerId);
    // })
    }
  }

  // sends a Message directly to peerId, without using other peers as
  // intermediaries if possible
  sendDirectMessage(msgObj, peerId) {
    if (!msgObj instanceof Message) {
      //sending raw data, convert to message
      return; //bad message
    }

    let connection = this.connections[peerId];
    // if you add iroh support, just add another check on iroh
    // here we check the handshake for webrtc
    // if iroh is incomplete, add a check there
    if (connection.webrtc.handshakeStage <3) {
      console.log("handshake incomplete!");
      return;
    }
    this.sendPacket(msgObj.toPacket(), peerId);
    
  }

}

// the object for all messages sent between peers
class Message {
  // data is the actual data being sent
  // type is what type, such as 'handshake', 'newCategory', etc
  // status is a numerical descriptive status, and a verbose text status
  // returnCallback is whether or not it should run code when a response is returned
  // callback is the code to run
  // wrappedPeerObj is the peer to do things to
  constructor(data,
              type = 'message',
              status = {code: 200, message: "OK"},
              returnCallback = false,
              callback = (data) => {console.log("received callback", data)},
              wrappedPeerObj = userPeer) {
    this.data = data;
    // make sure it conforms to the spec
    if (typeof this.data != "object") this.data = {data: this.data};
    this.status = status;
    this.callback = callback;
    this.type = type;
    this.wrappedPeerObj = wrappedPeerObj;
    this.cw = wrappedPeerObj?.cw || cw;
    this.callbackId = this.cw.b64RandomBytes(64);
    this.returnCallback = returnCallback;
  }
  toPacket() {
    return {
      type: this.type,
      status: this.status,
      data: this.data,
    }
  }
  // obsolete code:
  getPackets() {
    const packets = [];
    Object.keys(this.channel.peers).forEach(peerId => {
      const connection = this.wrappedPeerObj.connections[peerId];
      if (!connection.open) return;
      const callbackId = sodium.to_base64(sodium.randombytes_buf(64));
      connection.callbacks ??= {};
      connection.callbacks[callbackId] = this.callback;
      const {encrypted, nonce} = cw.encryptMessage(JSON.stringify(this.data), connection.theirPublicKey, connection.ourKeyPair.privateKey);
      packets.push([peerId, {
        type: this.type,
        encrypted: sodium.to_base64(encrypted),
        nonce: sodium.to_base64(nonce),
        signatures: {
          encrypted: sodium.to_base64(cw.signMessage(encrypted)),
          nonce: sodium.to_base64(cw.signMessage(nonce))
        },
        isEncrypted: true,
        callbackId: this.callbackId,
        returnCallback: this.returnCallback,
        status: this.status,
        channel: {
          id: this.channelId,
          creationDate: this.channel.creationDate,
          name: this.channel.name,
          description: this.channel.description,
          peers: this.channel.peers
        }
      }])
    });
    return packets;
  }

}
