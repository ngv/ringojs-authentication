export('authenticate');

var {basicauth} = require('config');
var strings = require('ringo/utils/strings')

/**
 * This module expects to have an object named 'basicauth' defined in the config module
 * The object is expected to have properties with usernames, and the values of those properties
 * as SHA1 hashes of the users password.
 *
 * basicauth passwords can be generated using the ringojs cmdline:
 *
 * require('ringo/util/strings').digest('secret-password','sha1')
 */
function authenticate(username, password) {
    require('ringo/shell').writeln('auth:'+username+" p:"+password);

    if (basicauth[username] && (basicauth[username] == strings.digest(password, 'sha1')) ) {
        return true;
    } else {
        return false;
    }
}