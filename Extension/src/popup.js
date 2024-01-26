var socket;
var url;

function connectSocket() {
  if (socket == undefined || !socket.readyState) {
    socket = new WebSocket('ws://localhost:30015');
  }
    

  socket.onopen = () => {
    console.log('WebSocket connection opened');
  };
  socket.onmessage = (event) => {
    let r = event.data;
    console.log(`Received message: ${r}`);
    getMessage(r);
  };

  socket.onclose = () => {
    console.log('WebSocket connection closed');
    setTimeout(connectSocket,1000)
  };
}
connectSocket();

function sendMessage(message) {
  if (socket.readyState){
    socket.send(message);
  }
}

chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
  const currentTab = tabs[0];
  const currentURL = currentTab.url;
  let arr = currentURL.split("/");
  url = arr[0]+"//"+arr[2]
});


function getMessage(message) {
  const SearchDiv1 = document.getElementById("SearchResult1");
  const SearchDiv2 = document.getElementById("SearchResult2");
  const SearchDiv3 = document.getElementById("SearchResult3");
  const resultDiv = document.getElementById("result");
  const loggedresultDiv = document.getElementById("loggedresult");
  const loginForm = document.getElementById("loginForm");
  const loggedInForm = document.getElementById("loggedInForm");
  const CopynameButton = document.getElementById("CopynameButton");

  var strArr = message.split("@@@@")
  console.log(strArr);
  var operate = strArr[0]

  if (strArr[1] == "Invalid token"){
    loginForm.style.display = "block"; 
    loggedInForm.style.display = "none"; 
    resultDiv.textContent = "Please Login Again";  
  }
  // 0:login 1:register 2:add 3:search 5:state
  
  if (operate == 5){
    noclientForm.style.display = "none"; 
    loginForm.style.display = "block"; 
    if (strArr[1]=='1'){
      loginForm.style.display = "none"; 
      loggedInForm.style.display = "block"; 
    }
  }
  else if (operate == 0){
    if (strArr[1]=='1'){
      loginForm.style.display = "none"; 
      loggedInForm.style.display = "block"; 
      resultDiv.textContent = "Login success!";
    }
    else{
      resultDiv.textContent = "Please Retry";
    }
  }
  else if(operate == 1){
    if (strArr[1]=='1'){
      resultDiv.textContent = "Register success!\nPlease Login.";
    }
    else{
      resultDiv.textContent = "Please Retry, maybe username has been used.";
    }
  }
  else if(operate == 2){
    loggedresultDiv.textContent = strArr[1];
  }

  else if(operate == 3){
    let account = strArr[1].split(';');
    if (account.length == 1){
      SearchDiv1.style.display = "block"; 
      SearchDiv2.style.display = "none";
      //SearchDiv3.style.display = "none";
      CopynameButton.style.display = "none";
      SearchDiv1.querySelector("p").textContent = account[0];
    } 
    else{
      CopynameButton.style.display = "block";
      SearchDiv1.style.display = "block"; 
      SearchDiv2.style.display = "block";
      SearchDiv1.querySelector("p").textContent = account[0];
      SearchDiv2.querySelector("p").textContent = account[1];
      //if (account.length == 3){
      //  SearchDiv3.style.display = "block";
      //  SearchDiv3.querySelector("p").textContent = account[2];
      //}
    }
  }
}

function copyToClip(text) {
  const textArea = document.createElement("textarea");
  textArea.value = text;
  document.body.appendChild(textArea);
  textArea.select();
  try {
    document.execCommand('copy');
  } catch (err) {
    console.error('Error', err);
  }
  document.body.removeChild(textArea);
}


function getState() {
  sendMessage("state");
}


setTimeout(getState,100)
document.addEventListener("DOMContentLoaded", function () {
  const loginButton = document.getElementById("loginButton");
  const RetryButton = document.getElementById("RetryButton");
  const registerButton = document.getElementById("RegisterButton");
  const NewButton = document.getElementById("NewButton");
  const SearchButton = document.getElementById("SearchButton");
  const SubmitButton = document.getElementById("SubmitButton");
  const CopynameButton = document.getElementById("CopynameButton");
  const CopypassButton = document.getElementById("CopypassButton");
  const showButton = document.getElementById("showButton");
  const showImage = document.getElementById("showImage");
  const logoutButton = document.getElementById("LogoutButton");
  const SearchDiv1 = document.getElementById("SearchResult1");
  const SearchDiv2 = document.getElementById("SearchResult2");
  const resultDiv = document.getElementById("result");
  const loggedresultDiv = document.getElementById("loggedresult");
  const loginForm = document.getElementById("loginForm");
  const loggedInForm = document.getElementById("loggedInForm");
  const NewForm = document.getElementById("NewForm");


  loginButton.addEventListener("click", function () {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    if (username && password) {
      sendMessage("login"+username+"@@@@"+password)
    } else {
      resultDiv.textContent = "Please Retry";
    }
  });

  registerButton.addEventListener("click", function () {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    if (username && password) {
      sendMessage("regis"+username+"@@@@"+password)
    } else {
      resultDiv.textContent = "Please Retry";
    }
  });

  NewButton.addEventListener("click", function () {
    if (NewForm.style.display == "block"){
      NewForm.style.display = "none"; 
    }
    else{
      NewForm.style.display = "block"; 
    }
  });

  SearchButton.addEventListener("click", function () {
    sendMessage("searc"+url)
  });

  SubmitButton.addEventListener("click", function () {
    const NewUsername = document.getElementById("NewUsername").value;
    const NewPassword = document.getElementById("NewPassword").value;
    //const NewRemark = document.getElementById("NewRemark").value;
    if (NewUsername && NewPassword) {
      sendMessage("add__"+url+"@@@@"+NewUsername+";"+NewPassword)//+";"+NewRemark)
    } else {
      loggedresultDiv.textContent = "Please Retry";
    }
  });
  RetryButton.addEventListener("click", function () {
    connectSocket();
    //console.log("retry");
    if(socket != undefined && socket.readyState){
      noclientForm.style.display = "none"; 
      loginForm.style.display = "block"; 
    }
  });

  logoutButton.addEventListener("click", function () {
    sendMessage("logou")
    loginForm.style.display = "block"; 
    loggedInForm.style.display = "none"; 
  });

  CopynameButton.addEventListener("click", function () {
    copyToClip(SearchDiv1.querySelector("p").textContent)
    
  });
  CopypassButton.addEventListener("click", function () {
    copyToClip(SearchDiv2.querySelector("p").textContent)
  });
  showButton.addEventListener("click", function () {
    console.log(showImage.src.split("/")[showImage.src.split("/").length-1]);
    if (showImage.src.split("/")[showImage.src.split("/").length-1] == "show.png"){
      showImage.src = "hide.png";
      SearchDiv2.querySelector("p").style.display = "inline";
    }
    else{
      showImage.src = "show.png";
      SearchDiv2.querySelector("p").style.display = "none";
    }
  });

});
