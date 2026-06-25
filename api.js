// This is the high level API to work on

function sync() {
  // Takes in the list of peers, requests for new content, and responds
  // to requests for new content
  // It then writes and updates the local database, and the actual
  // document structure
  //
  // This is the main syncing function for the global state
}


function post(message) {
  // This takes in a message object, and "posts" it.
  // That is, it sends it to all the peers, 
}

// TODO:
// See if this is the best spec.
// Perhaps a push/pull, or even a handleIncoming/request/push could
// be better, especially given that there are sockets and things meaning we
// don't *need* to periodically check for new peers


function addForum(forumID) {
  // Uses the forum identifier to add a new forum
  // The process to do that is the following:
  // 1) add it to the local list of forums
  // 2) find peers that use that forum
  // 3) request to sync with those peers by getting their list of peers,
  //    then using all of them to download the forum content
  // 4) display that data to the user, save to local db
}

function login() {
  // The primary startup function
  // This will init the db, connect to peers, and resync from last login
  // If we are doing user password encryption, this will use some sort
  // of auth so we can get the stuff ready

  
  dbInit();
  sync();
}
