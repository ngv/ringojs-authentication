var config = require('config').ADConfig;


var log = require('ringo/logging').getLogger(module.id);

export('authenticate', 'getUserFromEmail', 'getContext', 'findAttribute' );

/**
 * Authenticate the username/password combo using the NGV Active Directory server.
 *
 * Note the config needs to be set in your webapps config.js, in a property named 'ADConfig' as
 * an object with the following properties:
 * ADHost, ADPort, ADSearchBase, ADBrowserUsername, ADBrowserPassword
 *
 * @param {Object} username
 * @param {Object} password
 *
 * @return {Boolean}  true on success, false otherwise including any error conditions
 */
function authenticate(username, password) {

    if (!username || !password) {
        return false;
    }

    var url = config["ADUrl"];
    var searchBase = config["ADSearchBase"];
    var browserUser = config["ADBrowserUsername"];
    var browserPassword = config["ADBrowserPassword"];

    var context = null;

    var authResult = false;

    try {
        context = getContext(url, browserUser, browserPassword);
    } catch (e) {
        log.error("error in browser login");
        return false;
    }

    var dn = findAttribute('distinguishedName', 'sAMAccountName', username, searchBase, context);
    if (dn != null) {
        try {
            authResult = getContext(url, dn, password) ? true : false;
        } catch (e) {
            log.error("user login error:"+e);
            authResult = false;
        }
    }
    log.info("auth result:"+authResult);
    return authResult;
};

/**
 * @return {String}
 */
function getUserFromEmail(email) {
    var url = config["ADUrl"];
    var searchBase = config["ADSearchBase"];
    var browserUser = config["ADBrowserUsername"];
    var browserPassword = config["ADBrowserPassword"];

    try {
        var context = getContext(url, browserUser, browserPassword);
    } catch (e) {
        log.error("error in browser login");
        throw new Error("error in browser login");
    }

    return findAttribute('sAMAccountName',
                    'mail', email,
                    'ou=users,ou=ngv-office,dc=boh,dc=ngv,dc=local', context);
};


function getContext(url, userDN, password) {

    log.debug("doing getcontext() for:"+userDN);
    try {
        var Context =  Packages.javax.naming.Context;
        var InitialDirContext = Packages.javax.naming.directory.InitialDirContext;
        var env = new Packages.java.util.Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, url);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, userDN);
        env.put(Context.SECURITY_CREDENTIALS, password);
        return context = new InitialDirContext(env);
    } catch (e) {
        log.debug("error in AD getContext() user:"+userDN+"\n"+e);
        throw new Error("error in AD getContext() user:"+userDN+"\n"+e);
    }
}
//
//function findDN(attribute, value, searchBase, context) {
//    log.info("findDN:"+searchBase+"|"+attribute+"|"+value);
//
//    var searchControls = new Packages.javax.naming.directory.SearchControls();
//    searchControls.setSearchScope(Packages.javax.naming.directory.SearchControls.SUBTREE_SCOPE);
//    searchControls.setCountLimit(1);
//
//    var DN = "none";
//    var filter = "("+attribute+"="+value+")";
//    try {
//        var matchAttibutes = new Packages.javax.naming.directory.BasicAttributes(false);
//        matchAttibutes.put(new Packages.javax.naming.directory.BasicAttribute(attribute, value));
//
//        // Search for objects with these matching attributes
//        var result = context.search(searchBase, filter, searchControls);
//
//        if (result.hasMore()) {
//            var sr = result.next();
//            DN = sr.getAttributes().get("distinguishedName").toString().replace(/distinguishedName: /, "");
//            log.debug("search result:"+DN);
//        }
//    }
//    catch (e) {
//        log.error("error in AD findDN() :"+e);
//        return null;
//    }
//    return DN;
//}

function findAttribute(attribute, searchAttribute, value, searchBase, context) {
    log.info("findAtt:"+searchBase+"|"+attribute+"|"+value);

    var searchControls = new Packages.javax.naming.directory.SearchControls();
    searchControls.setSearchScope(Packages.javax.naming.directory.SearchControls.SUBTREE_SCOPE);
    searchControls.setCountLimit(1);

    var DN = "none";
    var filter = "("+searchAttribute+"="+value+")";
    try {
        var matchAttibutes = new Packages.javax.naming.directory.BasicAttributes(false);
        matchAttibutes.put(new Packages.javax.naming.directory.BasicAttribute(searchAttribute, value));

        // Search for objects with these matching attributes
        var result = context.search(searchBase, filter, searchControls);

        if (result.hasMore()) {
            var sr = result.next();
            DN = sr.getAttributes().get(attribute).get();
            log.debug("search result:"+DN);
        }
    }
    catch (e) {
        log.error("error in AD findAttribute() :"+e);
        return null;
    }
    return DN;
}

