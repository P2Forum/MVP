let loadState = {
  loaded: false,
  sodiumLoaded: false,
  checkedIntegrity: false
}


//Run Check integrity once the document is loaded, and sodium is loaded, whichever comes last
document.addEventListener("DOMContentLoaded", () => {
  // window.init();
  loadState.loaded = true;
  if (loadState.sodiumLoaded) {
    // checkIntegrity(false,init);
  }
});

// window.sodium = {
//   onload: (_sodium) => {
//     sodium = _sodium;
//     loadState.sodiumLoaded = true;
//     if (loadState.loaded) {
//       window.init()
//     }
//   }
// };

function checkIntegrity(strict = true, callback) {
  return callback();
}

