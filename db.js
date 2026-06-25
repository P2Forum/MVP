// This is the stuff to deal with the database on the local file
//
//


// ======================
// ==other DB functions==
// ======================

function dbInit() {
  // checks if db is extant.
  // If it is, gets that db, otherwise, create a new one
}

function dbCreate() {
  // creates a new db and saves it
  // (for cases such as when there is no db,
  // or you want to wipe the current one)
}

function getLocalDb() {
  // may not be necessary
  // gets the local db, asssuming it exists
}

function dbSqueeze() {
  // culls db to smaller size by removing older entries.
  // Checks all connected peers if entries are stored beforehand
  // This allows backups of the db so that no data is properly lost
}

// ======================
// =DB writing functions=
// ======================

function dbWrite(content) {
  // takes in some content, writes it to local database
  // This will have to do some checking of what the content type is,
  // so it adds it effectively to the db so it can read it back later
}

function addMessage(message) {
  // This takes in a message object, and adds it to the db
}

function addCategory(category) {
  
}

function addTopic(topic) {
  
}

function addReply(reply) {
  
}

function addPeer(peer) {
  
}

// ======================
// =DB reading functions=
// ======================

function dbQuery(query) {
  // takes in a query object that states what it is looking for from
  // the db.
  // This can be things like categories and topics, or even
  // individual replies and other things.
}
function queryMessage(message) {
  
}

function queryCategory(category) {
  
}

function queryTopic(topic) {
  
}

function queryReply(reply) {
  
}

function queryPeer(peer) {
  
}
