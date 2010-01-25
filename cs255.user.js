// ==UserScript========
// @namespace      CS255
// @name           CS255-Rossin-Signorelli
// @description    CS255 - Assignment 1
// @include        http://twitter.com/*
// @include        https://twitter.com/*
// @exclude        http://twitter.com/invitations/*
// @exclude        http://twitter.com/help/*
// @exclude        http://twitter.com/logout
// @exclude        https://twitter.com/invitations/*
// @exclude        https://twitter.com/help/*
// @exclude        https://twitter.com/logout
// ==/UserScript==

/*

  Step 1: change filename, @namespace, @name, and @description above.
  Please use "CS255-Lastname1-Lastname2" with you and your partners last names
  to make our grading less painful.

  Firefox:
    http://www.mozilla.com/en-US/firefox/
  GreaseMonkey:
    https://addons.mozilla.org/en-US/firefox/addon/748
  GreaseMonkey Site:
    http://www.greasespot.net/
  GreaseMonkey Wiki (manual, tutorials, etc..)
    http://wiki.greasespot.net/Main_Page
  Javascript reference and tutorials
    http://www.w3schools.com/js/default.asp
  Firebug
    https://addons.mozilla.org/en-US/firefox/addon/1843
  And of course... 2009 time waster of the year... Twitter
    (You'll want a throw-away account)
    http://www.twitter.com/

  Tips:
    Firefox "Tools"/"Error Console" - is where error messages go.
    Firebug rocks for looking at the webpage and debugging, use it.
*/

var my_username;   // user signed in as
var page_username; // the owner of the page being viewed
var tweets;        // array of the tweeys on the page
var current_group; // selected group
var keys = [];     // array of keys, each key is a [ user, group, key ];
var KEYLEN = 4;		// number of words for the AES keys (e.g. 4 -> 4 words -> 16 bytes -> 128 bits)



//
// Some initialization functions are called at the very end of this script.
// After some things are declared it needs.



function Encrypt( tweet, author, group )
{
alert("Encrypt()");
	// checks
	if(tweet.length < 1) {
		alert("Try entering a tweet");
		return tweet;
	}
	if(tweet.indexOf('aes128:') == 0) {
		alert("Tweet cannot start with \"aes128:\"");
		return tweet;
	}
	if(group == undefined) {
		alert("Must select a group");
		return tweet;
	}
	
	// encrypt, add tag.
	var plainTweet = group + tweet;
	plainTweet = StringToIntArray(plainTweet);
	var key = GetKeyFromGroup(group);
	if(key === false) {	// error: no key was found, group does not exist!
		alert("Group not found");
		return tweet;
	}
	var encryptedTweet = AesEncryptionWrapper(key, plainTweet);
	encryptedTweet = ArrayToHexString(encryptedTweet);
	
	return 'aes128:' + encryptedTweet;
}




function Decrypt( tweet, author )
{
alert("Decrypt()");

	// decrypt, ignore the tag.
	if(tweet.indexOf('aes128:') == 0) {
		// sweep all group/keys to find the correct one
		for(var i in keys) {
			var group = keys[i][1];
			var key = keys[i][2];
			var decrtweet = tweet.substr('aes128:'.length);
			decrtweet = HexStringToArray(decrtweet);
			decrtweet = AesDecryptionWrapper(key, decrtweet);
			decrtweet = IntArrayToString(decrtweet);
			if(decrtweet.indexOf(group) == 0) {	// correct group/key found!
				decrtweet = decrtweet.substr(group.length);
				return tweet + '<br><font color="red"><b>' + author + ': </b>' + decrtweet + '</font>';
			}
		}
		
		// no key was found to decrypt the tweet
		return tweet;
	}
	else {
		return tweet;
	}
}



function GenerateKey()
{
alert("GenerateKey()");

	user = my_username;
	group = document.getElementById( 'gen-key-group' ).value;

	if ( group.length < 1 )	{
		alert( "You need to set a group" );
		return;
	}

	key = GenerateRandomArray(KEYLEN);
	if(key === false)			// if there is not enough entropy, abort
		return false;
	keyString = ArrayToHexString(key);
	
	new_key = [ user, group, keyString ];
	
	// try saving the keys
	var oldKeys = keys.slice(0);
	keys.push( new_key );
	var ret = SaveKeys();
	if(ret === false) {
		keys = oldKeys.slice(0);
		return false;
	}
	UpdateKeysTable();
}




function SaveKeys()
{
alert("SaveKeys()");

	// compact the keys in a string
	rows = [];
	for ( i in keys )
		rows[i] = keys[i][0] + '$' + keys[i][1] + '$'+ keys[i][2];

	allkeys = rows.join( '$$' );

	// encrypt and save on disk
	var masterPassword = GetMasterPassword(true);
	allkeys = "alltwitterkeys" + allkeys;		// a known string, to check when decrypting passwords
	allkeys = StringToIntArray(allkeys);
	var encryptedKeys = AesEncryptionWrapper(masterPassword, allkeys);
	if(encryptedKeys === false)
		return false;
	encryptedKeys = ArrayToHexString(encryptedKeys);
	
	GM_setValue( 'twit-keys', encodeURIComponent( encryptedKeys ) );
}




function LoadKeys()
{
alert("LoadKeys()");
	
	keys = [];
	saved = GM_getValue( 'twit-keys', false );
	if ( saved && saved.length > 2 ) {
		key_str = decodeURIComponent( saved );
		var encryptedKeys = HexStringToArray(key_str);
		var masterPassword = GetMasterPassword(true);
		decryptedKeys = AesDecryptionWrapper(masterPassword, encryptedKeys);
		decryptedKeys = IntArrayToString(decryptedKeys);

		var count = 2;
		while(decryptedKeys.indexOf("alltwitterkeys") != 0) {	// if master password is wrong: ask again until it's correct, or tries expire
			if(count == 0) {
				alert("Tries expired");
				return "";
			}
			--count;
			
			masterPassword = GetMasterPassword(false);
			encryptedKeys = HexStringToArray(key_str);
			decryptedKeys = AesDecryptionWrapper(masterPassword, encryptedKeys);
			decryptedKeys = IntArrayToString(decryptedKeys);
		}
		
		decryptedKeys = decryptedKeys.substr("alltwitterkeys".length);
		
		arr = decryptedKeys.split( '$$' );
		for ( i in arr )
			keys[i] = arr[i].split( '$' );
	}
}
/*
function LoadKeys()
{
alert("LoadKeys()");
	keys = [];
	saved = GM_getValue( 'twit-keys', false );
	if ( saved && saved.length > 2 ) {
		key_str = decodeURIComponent( saved );
		arr = key_str.split( '$$' );
		for ( i in arr ) {
			keys[i] = arr[i].split( '$' );
			// CS255-todo: plaintext keys were on disk?^M
		}
	}
}*/



//////////////////////////////////////////////////////////
//							//
//		Helper functions			//
//							//
//////////////////////////////////////////////////////////

function StringToIntArray(str){

     //Local variables
     var len, iter, index, calc; 

     //Return variables
     var int = new Array();

//      str = group + author + tweet;

     //Check to see if message is %(16 chars)
     len = str.length;
     if(len%16 != 0){
          iter = 16-(len%16);
          for(i=0; i<iter; i++){
               str += '\0'; //Pad with zeroes
          }
     }
     len = str.length;
//      document.write('PADDED: ' + str + ' ' + str.length + ' ');


     //Split into array of (4 char elements)
//      document.write('ARRAY: ');
     for(i=0; i<len; i=i+4){
          int.push(str.substring(i,i+4));
//           document.write('[' + int[i] + '] ');
     }

     len = len/4;
     calc = [];
//      document.write('INT ARRAY: ');
     for(i=0; i<len; i++){
          str = '';
          for(j=0; j<4; j++){
               calc[j] = +(int[i].charAt(j)).charCodeAt();
               calc[j] = calc[j] << (8*j);
          }  
          int[i] = calc[0]+calc[1]+calc[2]+calc[3];
//           document.write('[' + int[i] + '] ');
     }

     return int;

}


function ArrayToHexString(intarray){

     //Local variables
     var word, num, len;

     //Return variables
     var str = new String();

     len = intarray.length;
     for(i=0; i<len; i++){
          num = +intarray[i];	
          num += 2147483648;
          var s = num.toString(16);	// convert to hex
          s = Array(9 - s.length).join('0') + s;	
          str += s;
     }
     str = str + '';
//      document.write('HEX STRING: ' + str + ' ');

     return str;

}


function HexStringToArray(hexstring){

     //Local variables
     var len, index, temp;

     //Return variables
     var intarray = new Array();

     len = hexstring.length;
//      document.write('INT ARRAY: ');
     for(i=0; i<len; i=i+8){
          temp = parseInt(hexstring.substring(i,i+8),16);
          temp -= 2147483648; 
          //temp = Array(9 - temp.length).join('0') + temp;
          intarray.push(+temp);
          index = i/8;
//           document.write('[' + intarray[index] + '] ');
     }

     return intarray;

}


function IntArrayToString(intarray){

     //Local variables
     var len, temp, tempstr;

     //Return variable
     var str = new String();

     len = intarray.length; 
     str = '';
    
//      document.write('STRING: ');
     for(i=0; i<len; i++){
          tempstr = '';
          for(j=0; j<4; j++){
               temp = intarray[i]%256;
               //document.write(temp + ' ');
               intarray[i] = intarray[i]>>8;
               tempstr = tempstr + String.fromCharCode(temp);;
          }  
          str = str + tempstr;
     }
     str = str + '';
//      document.write(str + ' ' + str.length);

     len = str.length;
     for(i=0; i<len; i++){
          if(str.charAt(i) == '\0'){
//                document.write('OUTPUT: ' + str.substring(0,i));
               return str.substring(0,i);
          }
     }
     return str;

}



/*
 * Gets the master password, either from a cookie or asking the user.
 * If checkCookie == true, first the cookie is checked, and if there isn't one, the password is asked;
 * if checkCookie == false, the cookie is not checked, and the password must be manually entered by the user.
 */
function GetMasterPassword(checkCookie)
{
	var masterpass;
	
	if(checkCookie === true)
		masterpass = GetCookie("master_password");
	
	if(checkCookie === false || masterpass == "") {
		masterpass = prompt("Enter secret master password", "");
		SetCookie("master_password", masterpass);
	}
	
	return masterpass;
}



/*
 * PRG based on GetEntropy(), which is used to generate a random IV and AES key
 * (just the first time: these values are then saved in a cookie and used/updated for the whole session).
 * Returns an array of "len" 32-bit random words.
 */
function GenerateRandomArray(len)
{
	// get PRG parameters from the cookies
	var key = GetCookie("PRG_key");
	var rndvalue = GetCookie("PRG_rndvalue");
//alert(key);
//alert(rndvalue);

	// if the parameters were not saved (this is the first time the function is called), generate them with GetEntropy()
	if(key == "" || rndvalue == "") {
		var word;
		var newKey = new Array();
		var iv = new Array();

		// generate the random key; if there is not enough entropy, abort
//alert("key");
		for(var ii = 0; ii < 4; ++ii) {
			word = GetEntropy();
//alert(word);
			if(word === false)
				return false;

			newKey.push(word);
		}

		// generate the random IV; if there is not enough entropy, abort
		for(var jj = 0; jj < 4; ++jj) {
			word = GetEntropy();
			if(word === false)
				return false;

			iv.push(word);
		}

		// assign the new generated values
		key = newKey;
		rndvalue = iv;
	}
	else {
		key = HexStringToArray(key);
		rndvalue = HexStringToArray(rndvalue);
	}
//alert(key);
//alert(rndvalue);


	// use {key, rndvalue} to generate the requested words (PRG)
	var randomWords = new Array();
	var nBlocks = Math.ceil(len / 4);	// AES can generate only 4 32-bit words at a time... we'll slice the array later
//alert(nBlocks);
	var cipher = new AES(key);

	for(var kk = 0; kk < nBlocks; ++kk) {	// keep feeding the rndvalue into the encryption block (chaining), and queue it into the array
		rndvalue = cipher.encrypt_core(rndvalue);
		randomWords = randomWords.concat(rndvalue);
	}
//alert(randomWords);
	randomWords = randomWords.slice(0, len);	// keep only the words that were requested
//alert(randomWords);

	// save PRG parameters to cookies
	key = ArrayToHexString(key);
	rndvalue = ArrayToHexString(rndvalue);
	SetCookie("PRG_key", key);
	SetCookie("PRG_rndvalue", rndvalue);


	return randomWords;
}



/*
 * Wrapper of the encryption core.
 * Given a plaintext, it encrypts it using CBC with a random IV.
 * NOTE: the plaintext MUST be already padded, the array length must be a multiple of 4 32-bit words.
 */
function AesEncryptionWrapper(key, plaintext)
{
	var xorBlock = GenerateRandomArray(4);	// generate a random 128-bit IV for the first round
	if(xorBlock === false)			// if there is not enough entropy, abort
		return false;
//var xorBlock = [1, 2, 3, 4];		// IV for the first round, encrypted block for the following rounds
	var cipher = new AES(key);
	var ciphertext = new Array();		// the ciphertext is prepended with the random IV
	ciphertext = ciphertext.concat(xorBlock);

	while(plaintext.length > 0) {		// for all blocks...
		var plainBlock = plaintext.splice(0, 4);		// get the first 4 words (i.e. one block)
		var cipherBlock = XorArrays(plainBlock, xorBlock);	// XOR the plain block with the previous cipher block...
		cipherBlock = cipher.encrypt_core(cipherBlock);		// ... and encrypt it with the key
		ciphertext = ciphertext.concat(cipherBlock);		// append the block to the ciphertext
		xorBlock = cipherBlock;					// prepare the XOR for the next block
	}

	// emit the ciphertext
	return ciphertext;
}



/*
 * Wrapper of the decryption core.
 * Given a ciphertext (with the random IV prepended to the message), it decrypts it using CBC.
 * NOTE: the ciphertext is returned as an array of 32-bit words, with the padding (if any).
 */
function AesDecryptionWrapper(key, ciphertext)
{
	var xorBlock = ciphertext.splice(0, 4);		// get the IV for the first round, encrypted block for the following rounds
	var cipher = new AES(key);
	var plaintext = new Array();

	while(ciphertext.length > 0) {
		var cipherBlock = ciphertext.splice(0, 4);
		var plainBlock = cipher.decrypt_core(cipherBlock);
		plainBlock = XorArrays(plainBlock, xorBlock);
		plaintext = plaintext.concat(plainBlock);
		xorBlock = cipherBlock;
	}

	return plaintext;
}



/*
 * Given two arrays of 32-bit words with the same length, it XORs the arrays words by word.
 */
function XorArrays(arr1, arr2)
{
	var len = arr1.length;
	var res = new Array();
	var i;

	for(i = 0; i < len; ++i) {
		var xored = arr1[i] ^ arr2[i];
		res.push(xored);
	}

	return res;
}



/*
 * Given the cookie name and value, sets a cookie that expires when the browser closes (i.e. no expiration date).
 */
function SetCookie(name, value)
{
	document.cookie = name + "=" + escape(value);
}



/*
 * Given the cookie name, recovers the value and returns it.
 * If there is no cookie with that name, it returns false.
 */
function GetCookie(name)
{
	if(document.cookie.length > 0) {
		c_start = document.cookie.indexOf(name + "=");
//alert(c_start);	// FIXME: remove
		if(c_start != -1) {
			c_start = c_start + name.length + 1;
			c_end = document.cookie.indexOf(";", c_start);
//alert(c_end);		// FIXME: remove
			if(c_end == -1)
				c_end = document.cookie.length;
//alert(unescape(document.cookie.substring(c_start, c_end)));	// FIXME: remove
			return unescape(document.cookie.substring(c_start, c_end));
		}
	}

	return "";
}



/*
 * Given a group, it returns the key of that group.
 */
function GetKeyFromGroup(group)
{
	for(var i in keys) {
		if (keys[i][1] === group) {
			return keys[i][2];
		}
	}
	
	return false;
}








/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////
//
// Should not _have_ to change anything below here.
// Helper functions and sample code.
//
/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////

function SetupUsernames()
{
  // get who you are logged in as, and whose page you are reading
  meta = document.getElementsByTagName( "meta" );
  for ( var i = 0; i < meta.length; i++ )
  {
    if ( meta[i].name == 'session-user-screen_name' )
    {
      my_username = meta[i].content;
    }
    //alert( "I am " + my_username );

    if ( meta[i].name == 'page-user-screen_name' )
    {
      page_username = meta[i].content;
    }
    else
    {
      page_username = my_username;
    }
    //alert( "Lookin at " + page_username );
  }
}

function AddElements()
{
  // Add another button that looks right, to encrypt tweets
  update = document.getElementsByClassName( "status-btn" );
  if ( update.length > 0 )
  {
    button = document.createElement( 'input' );
    button.type = 'button';
    button.id = 'encrypt-button';
    button.value = 'encrypt';
    button.className = 'status-btn round-btn'
    button.addEventListener( "click", DoEncrypt, false );
    update[0].appendChild( button );

    dropdown = document.createElement( 'select' );
    dropdown.id = 'group-dropdown';
    //button.addEventListener( "change", ChangedGroup, false );
    dropdown.addEventListener( "change", ChangedGroup, false );

    for ( i in keys )
    {
      if ( keys[i][0] == my_username )
      {
        item = document.createElement( 'option' );
        item.vaue = keys[i][1];
        item.innerHTML = keys[i][1];
        dropdown.appendChild( item );
      }
    }

    update[0].appendChild( dropdown );
  }

  tab = document.getElementById( 'password_tab' );
  if ( tab )
  {
    tab.innerHTML = 'Password/Encryption';
  }
  tab = document.getElementById( 'tab_password' );
  if ( tab && tab.innerHTML.length < 20 )
  {
    tab.innerHTML = 'Password/Encryption';
  }

  // On the account/password page, show the key setups
  if ( document.URL.match( 'account/password' ) )
  {
    div = document.getElementsByClassName( 'content-section' )[0];
    if ( div )
    {
      h2 = document.createElement( 'h2' );
      h2.innerHTML = "CS255 Keys";
      div.appendChild( h2 );

      table = document.createElement( 'table' );
      table.id = 'keys-table';
      table.setAttribute( 'cellpadding', 3 );
      table.setAttribute( 'cellspacing', 1 );
      table.setAttribute( 'border', 1 );
      table.setAttribute( 'width', "80%" );
      div.appendChild( table );
    }
  }
}

function UpdateKeysTable()
{
  table = document.getElementById( 'keys-table' );
  if ( !table ) return;
  table.innerHTML = '';

  // ugly due to events + GreaseMonkey.

  // header
  row = document.createElement( 'tr' );
  th = document.createElement( 'th' );
  th.innerHTML = "User"; row.appendChild( th );
  th = document.createElement( 'th' );
  th.innerHTML = "Group"; row.appendChild( th );
  th = document.createElement( 'th' );
  th.innerHTML = "Key"; row.appendChild( th );
  th = document.createElement( 'th' );
  th.innerHTML = "&nbsp;"; row.appendChild( th );
  table.appendChild( row );

  // keys
  for ( i = 0 ; i < keys.length ; i++ )
  {
    row = document.createElement( 'tr' );
    td = document.createElement( 'td' );
    td.innerHTML = keys[i][0];
    row.appendChild( td );
    td = document.createElement( 'td' );
    td.innerHTML = keys[i][1];
    row.appendChild( td );
    td = document.createElement( 'td' );
    td.innerHTML = keys[i][2];
    row.appendChild( td );
    td = document.createElement( 'td' );

    button = document.createElement( 'input' );
    button.type = 'button';
    button.value = 'Delete';
    button.addEventListener( "click", function(event)
      {
        DeleteKey( event.target.parentNode.parentNode.rowIndex - 1 );
      }, false );
    td.appendChild( button );
    row.appendChild( td );

    table.appendChild( row );
  }

  // add friend line
  row = document.createElement( 'tr' );

  td = document.createElement( 'td' );
  td.innerHTML = '<input id="new-key-user" type="text" size="16">';
  row.appendChild( td );

  td = document.createElement( 'td' );
  td.innerHTML = '<input id="new-key-group" type="text" size="8">';
  row.appendChild( td );

  td = document.createElement( 'td' );
  td.innerHTML = '<input id="new-key-key" type="text" size="24">';
  row.appendChild( td );

  td = document.createElement( 'td' );
  button = document.createElement( 'input' );
  button.type = 'button';
  button.value = 'Add Friend';
  button.addEventListener( "click", AddKey, false );
  td.appendChild( button );
  row.appendChild( td );

  table.appendChild( row );

  // generate line
  row = document.createElement( 'tr' );

  td = document.createElement( 'td' );
  td.innerHTML = my_username;
  row.appendChild( td );

  td = document.createElement( 'td' );
  td.innerHTML = '<input id="gen-key-group" type="text" size="8">';
  row.appendChild( td );

  table.appendChild( row );

  td = document.createElement( 'td' );
  td.colSpan = "2";
  button = document.createElement( 'input' );
  button.type = 'button';
  button.value = 'Generate New Key';
  button.addEventListener( "click", GenerateKey, false );
  td.appendChild( button );
  row.appendChild( td );

}

function AddKey()
{
  u = document.getElementById( 'new-key-user' ).value;
  g = document.getElementById( 'new-key-group' ).value;
  k = document.getElementById( 'new-key-key' ).value;
  new_key = [ u, g, k ];
/*  keys.push( new_key );
  SaveKeys();
  UpdateKeysTable();*/
	var oldKeys = keys.slice(0);
	keys.push( new_key );
	var ret = SaveKeys();
	if(ret === false) {
		keys = oldKeys.slice(0);
		return false;
	}
	UpdateKeysTable();
}

function DeleteKey( n )
{
/*  keys.splice( n, 1 );
  ret = SaveKeys();
  UpdateKeysTable();*/
	var oldKeys = keys.slice(0);	// deep copy
	keys.splice( n, 1 );
	var ret = SaveKeys();
	if(ret === false) {
		keys = oldKeys.slice(0);
		return false;
	}
	UpdateKeysTable();
}

function DoEncrypt()
{
  // triggered by the button
  box = document.getElementById( 'status', 'status_update_form' );
  box.value = Encrypt( box.value, my_username, current_group );
}

function ChangedGroup()
{
  // user changed to a new group key to use
  current_group = document.getElementById( 'group-dropdown' ).value;
}

function HarvestTweets()
{
  timeline =  document.getElementById( 'timeline' );
  if ( timeline )
  {
    tweets = timeline.getElementsByClassName('status');
  }
}

function GetTweetAuthor( n )
{
  a = tweets[n].getElementsByClassName('tweet-url screen-name')[0];
  if ( a )
    return a.innerHTML;
  else
    return page_username;
}

function GetTweetText( n )
{
  t = tweets[n].getElementsByClassName('entry-content')[0];
  if ( !t )
    t = tweets[n].getElementsByClassName('msgtxt')[0]; // search pages

  return t.innerHTML;
}

function SetTweetText( n, new_text )
{
  t = tweets[n].getElementsByClassName('entry-content')[0];
  if ( t )
    t.innerHTML = new_text;
  else
    tweets[n].getElementsByClassName('msgtxt')[0].innerHTML = new_text;
}

function DecryptTweets()
{
  for ( i in tweets )
  {
    txt = GetTweetText( i );
    auth = GetTweetAuthor( i );
    SetTweetText( i, Decrypt( txt, auth ) );
  }
}

function CryptoInit()
{
  Random.start_collectors();
}

function GetEntropy()
{
//	return Random.random_word( 6 );		// FIXME FIXME FIXME
   if ( Random.get_progress() >= 1.0 )
   {
     return Random.random_word( 6 );
   }
   else
   {
     alert( "Not enough entropy. After clicking OK, move your mouse around for a few seconds before trying again." );
     return false;
   }
}

function rot13( text )
{
  // JS rot13 from http://jsfromhell.com/string/rot13
  return text.replace(/[a-zA-Z]/g,
    function(c)
    {
      return String.fromCharCode(
        ( ( c <= "Z" ? 90 : 122 ) >=
        ( c = c.charCodeAt(0) + 13 ) ) ? c : c - 26 );
    } );
}

/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////
//
// Below here is from other libraries. Here be dragons.
//
/////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////



/*
Here are the basic cryptographic functions you need to do the assignment:

function AES(key)

This function creates a new AES encryptor/decryptor with a given key.
Note that the key must be an array of 4, 6, or 8 32-bit words for the
function to work.  For those of you keeping score, this constructor does
all the scheduling needed for the cipher to work.

encrypt_core: function(plaintext)

This function encrypts the given plaintext (duh).  The plaintext argument
should take the form of an array of four (32-bit) integers, so the plaintext
should only be one block of data.

decrypt_core: function(ciphertext)

This function decrypts the given ciphertext.  Again, the ciphertext argument
should be an array of 4 integers.

A silly example of this in action:

	var key1 = new Array(8);
	var cipher = new AES(key1);
	var dumbtext = new Array(4);
	dumbtext[0] = 1; dumbtext[1] = 2; dumbtext[2] = 3; dumbtext[3] = 4;
	var ctext = cipher.encrypt_core(dumbtext);
	var outtext = cipher.decrypt_core(ctext);

Obviously our key is just all zeroes in this case, but this should illustrate
the point.
*/


/* Javascript AES implementation.
 *
 * 2008, Mike Hamburg
 * Public domain.
 *
 * Portions of this code are cribbed from OpenSSL's aes_core.c (aka
 * rijndael-alg-fst.c).
 *
 * aes_core.c: 2000, Vincent Rijmen,  Antoon Bosselaers, Paulo Barreto
 * Also public domain.
 *
 * Crush this to strip out the comments and shorten the local
 * variables if you care about transfer speed.
 *
 * This is development code, i.e. it's not done yet.  It has little to
 * no error checking, hasn't been tested much, and may have serious
 * bugs.  What's more, the high-level API is incomplete.  Don't use it
 * for anything serious.
 */

/* Create a new AES encryptor/decryptor with a given key.
 *
 * The key must be an array of 4, 6, or 8 32-bit words.
 *
 */
function AES(key) {
  with(this){
    if (!computed)
      precompute();

    schedule_encrypt(key);
    schedule_decrypt();
  }
}

/* Prototype for storing AES precomputation tables */
AES.prototype = {

// Round constants for key schedule.
rcon:[0x01,0x02,0x04,0x08,0x10,
      0x20,0x40,0x80,0x1b,0x36],

// Have te and td been filled yet?
computed:false,

/* Precompute the te and td arrays.
 * They're kind of big (8.7K), so we eat a few milliseconds computing
 * them instead of transferring them.
 */
precompute: function() {
  var x,xi,sx,tx,tisx,i;
  var te=[[],[],[],[],[]],td=[[],[],[],[],[]],d=[];

  /* compute double table */
  for (x=0;x<256;x++) {
    // d[x]= x&128 ? x<<1 ^ 0x11b : x<<1;
    d[x] = x<<1 ^ (x>>7)*0x11b; // shorter but less clear.
  }

  /* Compute the round tables.
   *
   * We'll need access to x and x-1, which we'll get by walking
   * GF(28) as generated by (82,5).
   */
  for(x=xi=0;;) {
    // compute sx := sbox(x)
    sx = xi^ xi<<1 ^ xi<<2 ^ xi<<3 ^ xi<<4;
    sx = sx>>8 ^ sx&0xFF ^ 0x63;

    var dsx = d[sx], x2=d[x],x4=d[x2],x8=d[x4];

    // te(x) = rotations of (2,1,1,3) * sx
    tx   = dsx<<24 ^ sx<<16 ^ sx<<8 ^ sx^dsx;

    // similarly, td(sx) = (E,9,D,B) * x
    tisx = (x8^x4^x2) <<24 ^
           (x8^x    ) <<16 ^
           (x8^x4^x ) << 8 ^
           (x8^x2^x );

    // This can be done by multiplication instead but I think that's less clear
    // tisx = x8*0x1010101 ^ x4*0x1000100 ^ x2*0x1000001 ^ x*0x10101;
    // tx = dsx*0x1000001^sx*0x10101;

    // rotate and load
    for (i=0;i<4;i++) {
      te[i][x]  = tx;
      td[i][sx] = tisx;
      tx   =   tx<<24 | tx>>>8;
      tisx = tisx<<24 | tisx>>>8;
    }

    // te[4] is the sbox; td[4] is its inverse
    te[4][ x] = sx;
    td[4][sx] =  x;


    // wonky iteration goes through 0
    if (x==5) break;
    if (x) {
      x   = x2^d[d[d[x8^x2]]]; // x  *= 82 = 0b1010010
      xi ^= d[d[xi]];          // xi *= 5  = 0b101
    } else {
      x=xi=1;
    }
  }

  // We computed the arrays out of order.  On Firefox, this matters.
  // Compact them.
  for (i=0; i<5; i++) {
    te[i] = te[i].slice(0);
    td[i] = td[i].slice(0);
  }

  // Load up the AES prototype with the data
  var p = AES.prototype;
  p.te=te; p.td=td; p.computed=true;
},

/* Schedule encryption with key k into rke.  This is called
 * automatically by the constructor.
 */
schedule_encrypt: function(k) {
  var i,j=0,nk=k.length,nr=6+nk;
  var rke=[];

  var s = this.te[4];

  for (i=0; i<nk; i++) {
    rke[i] = k[i];
  }

  // Cribbed from OpenSSL.
  for (i=nk; i<4*(nr+1); i++) {
    var temp  = rke[i-1];

    if (i % nk == 0) {
      temp =
	s[temp >>> 16 & 0xff] << 24 ^
	s[temp >>>  8 & 0xff] << 16 ^
	s[temp        & 0xff] <<  8 ^
	s[temp >>> 24       ]       ^
	this.rcon[j] << 24;
      j++;
    } else if (nk == 8 && i % nk == 4) {
      temp =
	s[temp >>> 24       ] << 24 ^
	s[temp >>> 16 & 0xff] << 16 ^
	s[temp >>>  8 & 0xff] <<  8 ^
	s[temp        & 0xff];
    }

    rke[i] = rke[i-nk] ^ temp;
  }
  this.rke=rke;
},

/* Schedule decryption.
 *
 * Requires that the key has already been scheduled for encryption.
 *
 * Any high-level decryption function must make sure that this has
 * been called before decrypting, since in the future it probably
 * won't be called by the constructor.
 */
schedule_decrypt: function() {
  var rkd = [], rke=this.rke, t=rke.length, i, j;
  var s = this.te[4], td=this.td;

  /* Heavily reworked, originally from OpenSSL.  This is rerolled into
   * loops because hopefully the loop handling in scheduling won't
   * dominate decryption time.
   */
  for (i=0; t; i++,t--) {
    var temp=0, ki = rke[i];
    if (i < 4 || t <= 4) temp=ki;
    else {
      for (j=0; j<4; j++) {
	temp ^= td[j][s[ki >>> 24]];
	ki = ki << 8;
      }
    }

    // Subkeys 1 and 3 are switched from how OSSL does it, so that the
    // core function can be the same for encrypt and decrypt.
    rkd[t&3 ? t : t-4] = temp;
  }

  // compact for Firefox.  Measurable improvement.
  this.rkd=rkd.slice(0);
},

/* Core en/decryption routine.  If called with decrypt=0 or undefined,
 * encrypts the input.  If called with decrypt != 0, decrypts the
 * input (assuming decryption has been scheduled).
 *
 * Takes input and gives output as a 4-element array of 32-bit words.
 */
core: function(ipt, decrypt) {
  var y0, y1, y2;
  var rk = decrypt ? this.rkd : this.rke;
  var nr = rk.length/4-1;
  var k=4, i;
  var t = decrypt ? this.td : this.te;

  // Pull the tables into scope.
  var t0=t[0], t1=t[1], t2=t[2], t3=t[3], s=t[4];

  // because of the way ShiftRows differs from InverseShiftRows, x1
  // and x3 have to be switched before and after during decryption.
  var x0=ipt[0]^rk[0], x1=ipt[decrypt ? 3 : 1]^rk[1], x2=ipt[2]^rk[2], x3=ipt[decrypt ? 1 : 3]^rk[3];

  // Core.  Cribbed from OpenSSL.  n-1 of the n rounds.
  for (i=1;i<nr;i++) {
    y0 = t0[x0 >>> 24       ] ^ t1[x1 >>> 16 & 0xff] ^
         t2[x2 >>>  8 & 0xff] ^ t3[x3        & 0xff] ^ rk[k];
    y1 = t0[x1 >>> 24       ] ^ t1[x2 >>> 16 & 0xff] ^
         t2[x3 >>>  8 & 0xff] ^ t3[x0        & 0xff] ^ rk[k+1];
    y2 = t0[x2 >>> 24       ] ^ t1[x3 >>> 16 & 0xff] ^
         t2[x0 >>>  8 & 0xff] ^ t3[x1        & 0xff] ^ rk[k+2];
    x3 = t0[x3 >>> 24       ] ^ t1[x0 >>> 16 & 0xff] ^
         t2[x1 >>>  8 & 0xff] ^ t3[x2        & 0xff] ^ rk[k+3];
    k+=4;
    x0=y0;x1=y1;x2=y2;
  }
  var out=[];

  // The last round has no MixColumns operation, so it has a different
  // structure.  Cribbed from OpenSSL but significantly modified.
  for (i=0;i<4;i++) {
    out[decrypt ? 3&-i : i] =
      s[x0 >>> 24       ] << 24 ^
      s[x1 >>> 16 & 0xff] << 16 ^
      s[x2 >>>  8 & 0xff] <<  8 ^
      s[x3        & 0xff]       ^
      rk[k];
    y0=x0;x0=x1;x1=x2;x2=x3;x3=y0;
    k++;
  }
  return out;
},

/* Encrypt the given plaintext.  Still not a high-level routine,
   because it takes plaintext as an array of 4 integers and does only
   one block.
 */
encrypt_core: function(plaintext) { return this.core(plaintext, 0) },

/* Encrypt the given ciphertext.  Still not a high-level routine,
   because it takes ciphertext as an array of 4 integers, does only
   one block, and assumes that the key has been scheduled for
   decryption.
 */
decrypt_core: function(ciphertext) { return this.core(ciphertext, 1) }

}

/*
jsCrypto

sha256.js
Mike Hamburg, 2008.  Public domain.
 */


function SHA256() {
  if (!this.k[0])
    this.precompute();
  this.initialize();
}

SHA256.prototype = {
  /*
  init:[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],

  k:[0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2],
  */

  init:[], k:[],

  precompute: function() {
    var p=2,i=0,j;

    function frac(x) { return (x-Math.floor(x)) * 4294967296 | 0 }

    outer: for (;i<64;p++) {
      for (j=2;j*j<=p;j++)
	if (p % j == 0)
	  continue outer;

      if (i<8) this.init[i] = frac(Math.pow(p,1/2));
      this.k[i] = frac(Math.pow(p,1/3));
      i++;
    }
  },

  initialize:function() {
    this.h = this.init.slice(0);
    this.word_buffer   = [];
    this.bit_buffer    = 0;
    this.bits_buffered = 0;
    this.length        = 0;
    this.length_upper  = 0;
  },

  // one cycle of SHA256
  block:function(words) {
    var w=words.slice(0),i,h=this.h,tmp,k=this.k;

    var h0=h[0],h1=h[1],h2=h[2],h3=h[3],h4=h[4],h5=h[5],h6=h[6],h7=h[7];

    for (i=0;i<64;i++) {
      if (i<16) {
	tmp=w[i];
      } else {
        var a=w[(i+1)&15], b=w[(i+14)&15];
        tmp=w[i&15]=((a>>>7^a>>>18^a>>>3^a<<25^a<<14) + (b>>>17^b>>>19^b>>>10^b<<15^b<<13) + w[i&15] + w[(i+9)&15]) | 0;
      }

      tmp += h7 + (h4>>>6^h4>>>11^h4>>>25^h4<<26^h4<<21^h4<<7) + (h6 ^ h4&(h5^h6)) + k[i];

      h7=h6; h6=h5; h5=h4;
      h4 = h3 + tmp | 0;

      h3=h2; h2=h1; h1=h0;

      h0 = (tmp + ((h1&h2)^(h3&(h1^h2))) + (h1>>>2^h1>>>13^h1>>>22^h1<<30^h1<<19^h1<<10)) | 0;
    }

    h[0]+=h0; h[1]+=h1; h[2]+=h2; h[3]+=h3;
    h[4]+=h4; h[5]+=h5; h[6]+=h6; h[7]+=h7;
  },

  update_word_big_endian:function(word) {
    var bb;
    if ((bb = this.bits_buffered)) {
      this.word_buffer.push(word>>>(32-bb) ^ this.bit_buffer);
      this.bit_buffer = word << bb;
    } else {
      this.word_buffer.push(word);
    }
    this.length += 32;
    if (this.length == 0) this.length_upper ++; // mmhm..
    if (this.word_buffer.length == 16) {
      this.block(this.word_buffer);
      this.word_buffer = [];
    }
  },

  update_word_little_endian:function(word) {
    word = word >>> 16 ^ word << 16;
    word = ((word>>>8) & 0xFF00FF) ^ ((word<<8) & 0xFF00FF00);
    this.update_word_big_endian(word);
  },

  update_words_big_endian: function(words) {
    for (var i=0; i<words.length; i++) this.update_word_big_endian(words[i]);
  },

  update_words_little_endian: function(words) {
    for (var i=0; i<words.length; i++) this.update_word_little_endian(words[i]);
  },

  update_byte:function(byte) {
    this.bit_buffer ^= (byte & 0xff) << (24 - (this.bits_buffered));
    this.bits_buffered += 8;
    if (this.bits_buffered == 32) {
      this.bits_buffered = 0;
      this.update_word_big_endian(this.bit_buffer);
      this.bit_buffer = 0;
    }
  },

  update_string:function(string) {
    throw "not yet implemented";
  },

  finalize:function() {
    var i, wb = this.word_buffer;

    wb.push(this.bit_buffer ^ (0x1 << (31 - this.bits_buffered)));
    for (i = (wb.length + 2) & 15; i<16; i++) {
      wb.push(0);
    }

    wb.push(this.length_upper);
    wb.push(this.length + this.bits_buffered);

    this.block(wb.slice(0,16));
    if (wb.length > 16) {
      this.block(wb.slice(0,16));
    }

    var h = this.h;
    this.initialize();
    return h;
  }
}

SHA256.hash_words_big_endian = function(words) {
  var s = new SHA256();
  for (var i=0; i<=words.length-16; i+=16) {
    s.block(words.slice(i,i+16));
  }
  s.length = i << 5; // so don't pass this function more than 128M words
  if (i<words.length)
    s.update_words_little_endian(words.slice(i));
  return s.finalize();
}

SHA256.hash_words_little_endian = function(words) {
  var w = words.slice(0);
  for (var i=0; i<w.length; i++) {
    w[i] = w[i] >>> 16 ^ w[i] << 16;
    w[i] = ((w[i]>>>8) & 0xFF00FF) ^ ((w[i]<<8) & 0xFF00FF00);
  }
  return SHA256.hash_words_big_endian(w);
}

/*

 jsCrypto

 * Random.js -- cryptographic random number generator
 * Mike Hamburg, 2008.  Public domain.
 *
 * This generator uses a modified version of Fortuna.  Fortuna has
 * excellent resilience to compromise, relies on a state file, and is
 * intended to run for a long time.  As such, it does not need an
 * entropy estimator.  Unfortunately, Fortuna's startup in low-entropy
 * conditions leaves much to be desired.
 *
 * This generator features the following modifications.  First, the
 * generator does not create the n-th entropy pool until it exhausts
 * the n-1-st.  This means that entropy doesn't get "stuck" in pools
 * 10-31, which will never be used on a typical webpage.  It also
 * means that the entropy will all go into a single pool until the
 * generator is seeded.
 *
 * Second, there is a very crude entropy estimator.  The primary goal
 * of this estimator is to prevent the generator from being used in
 * low-entropy situations.  Corresponding to this entropy estimator,
 * there is a "paranoia control".  This controls how many bits of
 * estimated entropy must be present before the generator is used.
 * The generator cannot have more than 256 bits of actual entropy in
 * the main pool; rather, the paranoia control is designed to deal
 * with the fact that the entropy estimator is probably horrible.
 *
 * Third, the "statefile" is optional and stored in a cookie.  As
 * such, it is not protected from multiple simultaneous usage, and so
 * is treated conservatively.
 */

Random = {
    /* public */
NOT_READY: 0,
READY: 1,
REQUIRES_RESEED: 2,

    /* generate one random word */
random_word: function(paranoia) {
    return this.random_words(1, paranoia)[0];
},

    /* generate nwords random words, and return them in an array */
random_words: function(nwords, paranoia) {
    var out = [], i, readiness = this.is_ready(paranoia);

    if (readiness == this.NOT_READY)
        throw("Random: generator isn't seeded!");

    else if (readiness && this.REQUIRES_RESEED)
        this._reseed_from_pools(!(readiness & this.READY));

    for (i=0; i<nwords; i+= 4) {
        if ((i+1) % this._max_words_per_burst == 0)
            this._gate();

        var g = this._gen_4_words();
        out.push(g[0],g[1],g[2],g[3]);
    }
    this._gate();

    return out.slice(0,nwords);
},

set_default_paranoia: function(paranoia) {
    this._default_paranoia = paranoia;
},

    /* Add entropy to the pools.  Pass data as an array, number or
     * string.  Pass estimated_entropy in bits.  Pass the source as a
     * number or string.
     */
add_entropy: function(data, estimated_entropy, source) {
    source = source || "user";

    var id = this._collector_ids[source] ||
    (this._collector_ids[source] = this._collector_id_next ++);

    var i, ty = 0;

    var t = new Date().valueOf();

    var robin = this._robins[source];
    if (robin == undefined) robin = this._robins[source] = 0;
    this._robins[source] = ( this._robins[source] + 1 ) % this._pools.length;

    switch(typeof(data)) {

        case "number":
            data=[data];
            ty=1;
            break;

        case "object":
            if (!estimated_entropy) {
                /* horrible entropy estimator */
                estimated_entropy = 0;
                for (i=0; i<data.length; i++) {
                    var x = data[i];
                    while (x>0) {
                        estimated_entropy++;
                        x = x >>> 1;
                    }
                }
            }
            this._pools[robin].update_words_big_endian([id,this._event_id++,ty||2,estimated_entropy,t,data.length].concat(data));
            break;

        case "string":
            if (!estimated_entropy) {
                /* English text has just over 1 bit per character of entropy.
                 * But this might be HTML or something, and have far less
                 * entropy than English...  Oh well, let's just say one bit.
                 */
                estimated_entropy = data.length;
            }
            this._pools[robin].update_words_big_endian([id,this._event_id++,3,estimated_entropy,t,data.length])
            this._pools[robin].update_string(data);
            break;

        default:
            throw "add_entropy: must give an array, number or string"
    }

    var old_ready = this.is_ready();

    /* record the new strength */
    this._pool_entropy[robin] += estimated_entropy;
    this._pool_strength += estimated_entropy;

    /* fire off events */
    if (!old_ready && this.is_ready())
        this._fire_event("seeded", Math.max(this._strength, this._pool_strength));

    if (!old_ready)
        this._fire_event("progress", this.get_progress());
},

    /* is the generator ready? */
is_ready: function(paranoia) {
    var entropy_required = this._PARANOIA_LEVELS[ paranoia ? paranoia : this._default_paranoia ];

    if (this._strength >= entropy_required) {
        return (this._pool_entropy[0] > this._BITS_PER_RESEED && new Date.valueOf() > this._next_reseed) ?
        this.REQUIRES_RESEED | this.READY :
        this.READY;
    } else {
        return (this._pool_strength > entropy_required) ?
        this.REQUIRES_RESEED | this.NOT_READY :
        this.NOT_READY;
    }
},

    /* how close to ready is it? */
get_progress: function(paranoia) {
    var entropy_required = this._PARANOIA_LEVELS[ paranoia ? paranoia : this._default_paranoia ];

    if (this._strength >= entropy_required) {
        return 1.0;
    } else {
        return (this._pool_strength > entropy_required) ?
        1.0 :
        this._pool_strength / entropy_required;
    }
},

    /* start the built-in entropy collectors */
start_collectors: function() {
    if (this._collectors_started) return;

    if (window.addEventListener) {
        window.addEventListener("load", this._load_time_collector, false);
        window.addEventListener("mousemove", this._mouse_collector, false);
    } else if (document.attachEvent) {
        document.attachEvent("onload", this._load_time_collector);
        document.attachEvent("onmousemove", this._mouse_collector);
    }
    else throw("can't attach event");

    this._collectors_started = true;
},

    /* stop the built-in entropy collectors */
stop_collectors: function() {
    if (!this._collectors_started) return;

    if (window.removeEventListener) {
        window.removeEventListener("load", this._load_time_collector);
        window.removeEventListener("mousemove", this._mouse_collector);
    } else if (window.detachEvent) {
        window.detachEvent("onload", this._load_time_collector);
        window.detachEvent("onmousemove", this._mouse_collector)
    }
    this._collectors_started = false;
},

use_cookie: function(all_cookies) {
    throw "TODO: implement use_cookie";
},

    /* add an event listener for progress or seeded-ness */
addEventListener: function(name, callback) {
    this._callbacks[name][this._callback_i++] = callback;
},

    /* remove an event listener for progress or seeded-ness */
removeEventListener: function(name, cb) {
    var i, j, cbs=this._callbacks[name], js_temp=[];

    /* I'm not sure if this is necessary; in C++, iterating over a
     * collection and modifying it at the same time is a no-no.
     */

    for (j in cbs)
        if (cbs.hasOwnProperty[j] && cbs[j] === cb)
            js_temp.push(j);

    for (i=0; i<js_temp.length; i++) {
        j = js[i];
        delete cbs[j];
    }
},

    /* private */
    _pools                   : [new SHA256()],
    _pool_entropy            : [0],
    _reseed_count            : 0,
    _robins                  : {},
    _event_id                : 0,

    _collector_ids           : {},
    _collector_id_next       : 0,

    _strength                : 0,
    _pool_strength           : 0,
    _next_reseed             : 0,
    _key                     : [0,0,0,0,0,0,0,0],
    _counter                 : [0,0,0,0],
    _cipher                  : undefined,
    _default_paranoia        : 8,

    /* event listener stuff */
    _collectors_started      : false,
    _callbacks               : {progress: {}, seeded: {}},
    _callback_i              : 0,

    /* constants */
    _MAX_WORDS_PER_BURST     : 65536,
    _PARANOIA_LEVELS         : [0,48,64,96,128,192,256,384,512,768,1024],
    _MILLISECONDS_PER_RESEED : 100,
    _BITS_PER_RESEED         : 80,

    /* generate 4 random words, no reseed, no gate */
_gen_4_words: function() {
    var words = [];
    for (var i=0; i<3; i++) if (++this._counter[i]) break;
    words = this._cipher.encrypt_core(this._counter);
    return words;
},

    /* rekey the AES instance with itself after a request, or every _MAX_WORDS_PER_BURST words */
_gate: function() {
    this._key = this._gen_4_words().concat(this._gen_4_words());
    this._cipher = new AES(this._key);
},

    /* reseed the generator with the given words */
_reseed: function(seedWords) {
    this._key = SHA256.hash_words_big_endian(this._key.concat(seedWords));
    this._cipher = new AES(this._key);
    for (var i=0; i<3; i++) if (++this._counter[i]) break;
},

    /* reseed the data from the entropy pools */
_reseed_from_pools: function(full) {
    var reseed_data = [], strength = 0;

    this._next_reseed = new Date().valueOf() + this._MILLISECONDS_PER_RESEED;

    for (i=0; i<this._pools.length; i++) {
        reseed_data = reseed_data.concat(this._pools[i].finalize());
        strength += this._pool_entropy[i];
        this._pool_entropy[i] = 0;

        if (!full && (this._reseed_count & (1<<i))) break;
    }

    /* if we used the last pool, push a new one onto the stack */
    if (this._reseed_count >= 1 << this._pools.length) {
        this._pools.push(new SHA256());
        this._pool_entropy.push(0);
    }

    /* how strong was this reseed? */
    this._pool_strength -= strength;
    if (strength > this._strength) this._strength = strength;

    this._reseed_count ++;
    this._reseed(reseed_data);
},

_mouse_collector: function(ev) {
    var x = ev.x || ev.clientX || ev.offsetX;
    var y = ev.y || ev.clientY || ev.offsetY;
    Random.add_entropy([x,y], 2, "mouse");
},

_load_time_collector: function(ev) {
    var d = new Date();
    Random.add_entropy(d, 2, "loadtime");
},

_fire_event: function(name, arg) {
    var j, cbs=Random._callbacks[name], cbs_temp=[];

    /* I'm not sure if this is necessary; in C++, iterating over a
     * collection and modifying it at the same time is a no-no.
     */

    for (j in cbs) {
        if (cbs.hasOwnProperty(j)) {
            cbs_temp.push(cbs[j]);
        }
    }

    for (j=0; j<cbs_temp.length; j++) {
        cbs_temp[j](arg);
    }
}
};

// This is the initialization

CryptoInit();
SetupUsernames();
LoadKeys();
AddElements();
UpdateKeysTable();
HarvestTweets();
DecryptTweets();