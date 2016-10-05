var GetOpts = require( 'node-getopt' );
var async   = require( 'async' );
var sprintf = require( 'sprintf-js' ).sprintf;

var Usage = [
  "node manage-user.js --config=./config.json --email=joe@com.com --operation=profile --firstname=Joe --middlename=J --lastname=Jones --new-email=jones@com.com",
  "node manage-user.js --config=./config.json --email=joe@com.com --operation=reset-password",
  "node manage-user.js --config=./config.json --email=joe@com.com --operation=disable",
  "node manage-user.js --config=./config.json --email=joe@com.com --operation=enable",
  "node manage-user.js --config=./config.json --email=joe@com.com --operation=unlock",
  "node manage-user.js --config=./config.json --operation=unlockall",
];

application();

function application() {

  var getopts = GetOpts.create([
    [ '', 'config[=FILENAME]', 'Full path/file to config' ],
    [ '', 'firstname[=FIRSTNAME]', 'First name of user' ],
    [ '', 'middlename[=MIDDLENAME]', 'Middle name of user' ],
    [ '', 'lastname[=LASTNAME]', 'Last name of user' ],
    [ '', 'email[=EMAIL]', 'Email of user' ],
    [ '', 'new-email[=EMAIL]', 'New email for user' ],
    [ '', 'operation[=OPERATION]', 'Operation to perform (profile, reset-password, disable, enable, unlock, unlockall)' ],

    [ 'h', 'help', 'Display this help' ],
  ]);
  //getopts.bindHelp();
  var opt = getopts.parseSystem();
  var options = opt.options;

  if ( options.help ) {
    console.log( Usage.join("\n") );
    process.exit( 0 );
  }

  if ( ! options.config ) {
    console.log( 'You must supply a config file!' );
    console.log( Usage.join("\n") );
    process.exit(1);
  }

  if ( ! options.operation ) {
    console.log( 'You must supplu an operation!' );
    console.log( Usage.join("\n") );
    process.exit(1);
  }
  
  var _config = require( options.config );
  var app = { log: require( 'winston' ), config: _config };

  app.config.logger = app.log;

  var userdb = require( '../index' );
  userdb.initialize( app, app.config );

  switch( options.operation ) {
    case 'profile':
      changeProfile( options );
      break;
    case 'reset-password':
      resetPassword( options );
      break;
    case 'disable':
      disableUser( options );
      break;
    case 'enable':
      enableUser( options );
      break;
    case 'unlock':
      unlockUser( options );
      break;
    case 'unlockall':
      unlockAll( options );
      break;
    default:
      console.log( 'Unrecognized operation!' );
      console.log( Usage.join("\n") );
      process.exit(1);
      break;
  }

  function exit( err ) {
    if ( err ) console.log( err );
    process.exit( ( err ? 1 : 0 ) );
  }

  function changeProfile( opts ) {
    var username = opts.email;
    if ( ! username ) {
      console.log( 'email is required!' );
      console.log( Usage.join("\n") );
      process.exit(1);
    }
    userdb.findUserByName( username, function( err, user ) {
      if ( err ) exit( err );
      if ( ! user ) exit( new Error( 'cannot find user with email=' + username ) );
      var u = {
	id: user.id,
	givenName: opts.firstname,
	middleName: opts.middlename,
	surname: opts.lastname,
	email: opts[ 'new-email' ]
      };
      userdb.saveUser( u, exit );
    });
  }

  function resetPassword( opts ) {
    var username = opts.email;
    if ( ! username ) {
      console.log( 'email is required!' );
      console.log( Usage.join("\n") );
      process.exit(1);
    }
    userdb.findUserByName( username, function( err, user ) {
      if ( err ) exit( err );
      if ( ! user ) exit( new Error( 'cannot find user with email=' + username ) );
      userdb.resetPassword( user, exit );
    });
  }

  function disableUser( opts ) {
    var username = opts.email;
    if ( ! username ) {
      console.log( 'email is required!' );
      console.log( Usage.join("\n") );
      process.exit(1);
    }
    userdb.findUserByName( username, function( err, user ) {
      if ( err ) exit( err );
      if ( ! user ) exit( new Error( 'cannot find user with email=' + username ) );
      userdb.saveUser({ id: user.id, status: 'DISABLED' }, exit );
    });
  }

  function enableUser( opts ) {
    var username = opts.email;
    if ( ! username ) {
      console.log( 'email is required!' );
      console.log( Usage.join("\n") );
      process.exit(1);
    }
    userdb.findUserByName( username, function( err, user ) {
      if ( err ) exit( err );
      if ( ! user ) exit( new Error( 'cannot find user with email=' + username ) );
      userdb.saveUser({ id: user.id, status: 'ENABLED' }, exit );    
    });
  }

  function unlockUser( opts ) {
    var username = opts.email;
    if ( ! username ) {
      console.log( 'email is required!' );
      console.log( Usage.join("\n") );
      process.exit(1);
    }
    userdb.findUserByName( username, function( err, user ) {
      if ( err ) exit( err );
      if ( ! user ) exit( new Error( 'cannot find user with email=' + username ) );
      userdb.unlockUser( user, exit );
    });
  }

  function unlockAll( opts ) {
    userdb.unlockUsers( exit );
  }

}
