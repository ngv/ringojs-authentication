var config = require('config').ADConfig;


var log = require('ringo/logging').getLogger(module.id);

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
exports.authenticate = function(username, password) {


    if (!username || !password) {
        return false;
    }

    var url = config["ADUrl"];
    var searchBase = config["ADSearchBase"];
    var browserUser = config["ADBrowserUsername"];
    var browserPassword = config["ADBrowserPassword"];

    var context = null;

    log.info("starting AD auth:"+url+"|"+searchBase+"|"+username);

    var getContext = function (userDN, password) {
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
            context = new InitialDirContext(env);
        } catch (e) {
            log.debug("error in AD getContext() user:"+userDN+"\n"+e);
            return false;
        }
        return true;
    }

    //note uses searchBase "outer" var
    var findDN = function(attribute, value) {
        var searchControls = new Packages.javax.naming.directory.SearchControls();
        searchControls.setSearchScope(Packages.javax.naming.directory.SearchControls.SUBTREE_SCOPE);
        searchControls.setCountLimit(1);

        var DN = "none";
        var filter = "("+attribute+"="+value+")";
        try {
            var matchAttibutes = new Packages.javax.naming.directory.BasicAttributes(false);
            matchAttibutes.put(new Packages.javax.naming.directory.BasicAttribute(attribute, value));

            // Search for objects with these matching attributes
            var result = context.search(searchBase, filter, searchControls);

            if (result.hasMore()) {
                var sr = result.next();
                DN = sr.getAttributes().get("distinguishedName").toString().replace(/distinguishedName: /, "");
                log.debug("search result:"+DN);
            }
        }
        catch (e) {
            log.error("error in AD findDN() :"+e);
            return null;
        }
        return DN;
    }

    var authResult = false;
    //users can login using ngv email OR windows username
    var searchAttribute = (username.indexOf('@') != -1) ? "mail" : "sAMAccountName";

    try {
        getContext(browserUser, browserPassword);
    } catch (e) {
        log.error("error in browser login");
        return false;
    }

    var dn = findDN(searchAttribute, username);
    if (dn != null) {
        try {
            authResult = getContext(dn, password) ? true : false;
        } catch (e) {
            log.error("user login error:"+e);
            authResult = false;
        }
    }
    log.info("auth result:"+authResult);
    return authResult;
}

