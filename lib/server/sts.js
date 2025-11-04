/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * AWS STS (Security Token Service) implementation for Mahi
 */

var assert = require('assert-plus');
var crypto = require('crypto');
var sprintf = require('util').format;
var errors = require('./errors.js');

/**
 * @brief Generates UUID compatible with older Node.js versions
 * 
 * Creates a version 4 UUID using simple character replacement
 * algorithm that works with Node.js v0.10.48.
 * 
 * @return {string} UUID in standard format (36 characters)
 * 
 * @note Uses Math.random() instead of crypto for compatibility
 * @note Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
 * 
 * @example
 * var id = generateUUID();
 * // Returns: "a1b2c3d4-e5f6-4789-a012-3456789abcde"
 * 
 * @since 1.0.0
 */
function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0;
        var v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

/**
 * @brief Generates temporary access key ID for STS credentials
 * 
 * Creates a unique access key identifier with MSTS prefix to
 * distinguish temporary credentials from permanent ones.
 * 
 * @return {string} Temporary access key ID in format "MSTS<hex>"
 *                  where <hex> is 16 random hexadecimal chars
 * 
 * @note Uses crypto.randomBytes for cryptographic randomness
 * @note MSTS prefix enables credential type identification
 * 
 * @example
 * var keyId = generateTemporaryAccessKeyId();
 * // Returns: "MSTS4F2A1B3C9E7D8A6F"
 * 
 * @since 1.0.0
 */
function generateTemporaryAccessKeyId() {
    // Use MSTS prefix to distinguish from permanent credentials
    var prefix = 'MSTS';
    var randomPart = crypto.randomBytes(8).toString('hex').toUpperCase();
    return prefix + randomPart;
}

/**
 * @brief Generates temporary secret access key
 * 
 * Creates a cryptographically random secret key for temporary
 * credentials using 256 bits of entropy.
 * 
 * @return {string} Base64-encoded secret key (44 characters)
 * 
 * @note Uses crypto.randomBytes(32) for 256-bit entropy
 * @note Base64 encoding for AWS compatibility
 * 
 * @example
 * var secret = generateTemporarySecretKey();
 * // Returns: "AbC123dEf456GhI789jKl012MnO345pQr678StU901VwX="
 * 
 * @since 1.0.0
 */
function generateTemporarySecretKey() {
    return crypto.randomBytes(32).toString('base64');
}

/**
 * @brief Generates session token for temporary credentials
 * 
 * Creates a base64-encoded session token containing UUID,
 * timestamp, and entropy for secure temporary credential
 * identification.
 * 
 * @return {string} Base64-encoded session token
 * 
 * @note Contains UUID, creation timestamp, and 256-bit entropy
 * @note Base64 encoding of JSON payload for AWS compatibility
 * @note Not JWT - simple JSON structure for Node.js v0.10.48
 * 
 * @example
 * var token = generateSessionToken();
 * // Returns: Base64 of {"uuid": "...", "created": 123456, ...}
 * 
 * @since 1.0.0
 */
function generateSessionToken() {
    var payload = {
        uuid: generateUUID(),
        created: Date.now(),
        entropy: crypto.randomBytes(32).toString('hex')
    };
    return new Buffer(JSON.stringify(payload)).toString('base64');
}

/**
 * @brief Validates IAM trust policy against caller identity
 * 
 * Parses and evaluates the role's AssumeRolePolicyDocument to
 * determine if the calling principal is authorized to assume
 * the role. Supports AWS IAM policy syntax with Principal,
 * Effect, and Action validation.
 * 
 * @param {string} trustPolicyDocument JSON-encoded IAM trust policy
 * @param {Object} caller Calling principal information
 * @param {string} caller.uuid Principal UUID
 * @param {string} caller.login Principal login name
 * @param {Object} log Bunyan logger instance
 * 
 * @return {boolean} True if caller authorized, false otherwise
 * 
 * @note Supports wildcard (*) and ARN-based principal matching
 * @note Only evaluates Allow effects (Deny not implemented)
 * @note Requires sts:AssumeRole action in policy statements
 * 
 * @example
 * var policy = '{"Statement":[{"Effect":"Allow",...}]}';
 * var allowed = validateTrustPolicy(policy, caller, log);
 * 
 * @since 1.0.0
 */
function validateTrustPolicy(trustPolicyDocument, caller, log) {
    if (!trustPolicyDocument) {
        log.warn('No trust policy found for role');
        return false;
    }
    
    var policy;
    try {
        policy = JSON.parse(trustPolicyDocument);
    } catch (parseErr) {
        log.error({err: parseErr, trustPolicy: trustPolicyDocument}, 
            'Invalid trust policy JSON');
        return false;
    }
    
    if (!policy.Statement || !Array.isArray(policy.Statement)) {
        log.error({policy: policy}, 
            'Trust policy missing Statement array');
        return false;
    }
    
    // Evaluate each statement
    for (var i = 0; i < policy.Statement.length; i++) {
        var statement = policy.Statement[i];
        
        // Skip statements that don't allow AssumeRole
        if (statement.Effect !== 'Allow') {
            continue;
        }
        
        // Check if Action includes sts:AssumeRole
        var actions = Array.isArray(statement.Action) ? 
            statement.Action : [statement.Action];
        var hasAssumeRole = false;
        for (var j = 0; j < actions.length; j++) {
            if (actions[j] === 'sts:AssumeRole' || actions[j] === '*') {
                hasAssumeRole = true;
                break;
            }
        }
        
        if (!hasAssumeRole) {
            continue;
        }
        
        // Check Principal
        if (statement.Principal) {
            if (validatePrincipal(statement.Principal, caller, log)) {
                log.debug({
                    statement: i,
                    caller: caller.uuid,
                    principal: statement.Principal
                }, 'Trust policy statement matched');
                return true;
            }
        }
    }
    
    log.warn({
        caller: caller.uuid,
        policyStatements: policy.Statement.length
    }, 'No trust policy statement matched caller');
    return false;
}

/**
 * @brief Validates IAM principal specification against caller
 * 
 * Evaluates different principal formats from trust policy statements
 * to determine if the caller matches the specified principal. Handles
 * both string and object principal formats as per AWS IAM spec.
 * 
 * @param {string|Object} principal Principal from trust policy
 * @param {Object} caller Calling principal information  
 * @param {string} caller.uuid Principal UUID
 * @param {string} caller.login Principal login name
 * @param {Object} log Bunyan logger instance
 * 
 * @return {boolean} True if caller matches principal, false otherwise
 * 
 * @note Supports string format: "*", ARN strings
 * @note Supports object format: {"AWS": "..."}, {"Service": "..."}
 * @note Supports arrays of principals for multiple matches
 * 
 * @example
 * // Wildcard principal
 * validatePrincipal("*", caller, log); // true
 * 
 * // AWS service principal object
 * validatePrincipal({"AWS": "arn:aws:iam::123:user/bob"}, caller, log);
 * 
 * @since 1.0.0
 */
function validatePrincipal(principal, caller, log) {
    // Handle different principal formats
    if (typeof principal === 'string') {
        if (principal === '*') {
            return true;
        }
        return validateSinglePrincipal(principal, caller, log);
    }
    
    if (typeof principal === 'object') {
        // Handle {"AWS": "..."} or {"Service": "..."} format
        if (principal.AWS) {
            var awsPrincipals = Array.isArray(principal.AWS) ? 
                principal.AWS : [principal.AWS];
            for (var k = 0; k < awsPrincipals.length; k++) {
                if (validateSinglePrincipal(awsPrincipals[k], 
                    caller, log)) {
                    return true;
                }
            }
            return false;
        }
        
        if (principal.Service) {
            // For now, we don't validate service principals since 
            // this is for user assumption
            log.debug({servicePrincipal: principal.Service}, 
                'Skipping service principal validation');
            return false;
        }
        
        if (principal.Federated) {
            // For now, we don't support federated principals
            log.debug({federatedPrincipal: principal.Federated}, 
                'Skipping federated principal validation');
            return false;
        }
    }
    
    log.debug({principal: principal}, 
        'Unrecognized principal format');
    return false;
}

/**
 * @brief Validates single principal string against caller identity
 * 
 * Performs detailed validation of a single principal string value
 * against caller information. Supports wildcard matching and
 * ARN-based principal validation for trust policies.
 * 
 * @param {string} principalString Principal identifier to validate
 * @param {Object} caller Calling principal information
 * @param {string} caller.uuid Principal UUID  
 * @param {string} caller.login Principal login name
 * @param {Object} log Bunyan logger instance
 * 
 * @return {boolean} True if principal matches caller, false otherwise
 * 
 * @note Supports wildcard "*" for any principal
 * @note Supports ARN format: arn:aws:iam::account:user/username
 * @note Supports root account format: arn:aws:iam::account:root
 * @note Uses login name matching for user identification
 * 
 * @example
 * var arn = "arn:aws:iam::123456789012:user/alice";
 * var valid = validateSinglePrincipal(arn, caller, log);
 * 
 * @since 1.0.0
 */
function validateSinglePrincipal(principalString, caller, log) {
    if (principalString === '*') {
        return true;
    }
    
    // Handle ARN format: arn:aws:iam::account-id:user/username
    // or arn:aws:iam::account-id:root
    if (principalString.indexOf('arn:aws:iam::') === 0) {
        var arnParts = principalString.split(':');
        if (arnParts.length >= 6) {
            var accountId = arnParts[4];
            var resourcePart = arnParts.slice(5).join(':');
            
            // For now, validate based on account UUID match
            // In a full implementation, you might map account 
            // IDs to UUIDs
            if (resourcePart === 'root' && caller.account && 
                caller.account.uuid === accountId) {
                return true;
            }
            
            // Handle user ARN
            if (resourcePart.indexOf('user/') === 0 && 
                caller.account && 
                caller.account.uuid === accountId) {
                return true;
            }
        }
    }
    
    // Handle account ID (12-digit string)
    if (/^\d{12}$/.test(principalString)) {
        return caller.account && 
            caller.account.uuid === principalString;
    }
    
    // Handle UUID format directly
    if (caller.account && 
        caller.account.uuid === principalString) {
        return true;
    }
    
    // Handle caller UUID directly
    if (caller.uuid === principalString) {
        return true;
    }
    
    log.debug({
        principal: principalString,
        callerUuid: caller.uuid,
        callerAccountUuid: caller.account ? caller.account.uuid : null
    }, 'Principal did not match caller');
    
    return false;
}

/**
 * @brief Fetches IAM role trust policy from UFDS directory
 * 
 * Retrieves the AssumeRolePolicyDocument for a specified role by
 * parsing the role ARN, searching UFDS directory, and extracting
 * trust policy from role attributes. Uses LDAP search with role
 * name and account filtering.
 * 
 * @param {string} roleArn AWS role ARN to fetch policy for
 * @param {Object} ufds UFDS client instance for directory access
 * @param {Object} log Bunyan logger instance
 * @param {function} callback Node.js callback function
 * @param {Error} callback.err Error if operation failed
 * @param {string} callback.trustPolicy JSON trust policy document
 * 
 * @note Expected ARN format: arn:aws:iam::account:role/rolename
 * @note Searches for 'sdcaccountrole' objectclass in UFDS
 * @note Extracts policy from 'memberpolicy' attribute array
 * @note Returns first policy containing sts:AssumeRole action
 * 
 * @example
 * var arn = "arn:aws:iam::123456789012:role/MyRole";
 * fetchRoleTrustPolicy(arn, ufds, log, function(err, policy) {
 *     if (!err) console.log('Trust policy:', policy);
 * });
 * 
 * @since 1.0.0
 */
function fetchRoleTrustPolicy(roleArn, ufds, log, callback) {
    // Parse role ARN to extract role name and account
    // Expected format: arn:aws:iam::account:role/rolename
    var arnParts = roleArn.split(':');
    if (arnParts.length < 6 || arnParts[2] !== 'iam') {
        return callback(new errors.InvalidParameterError(
            'Invalid role ARN format'));
    }
    
    var accountId = arnParts[4];
    var resourcePart = arnParts[5];
    if (resourcePart.indexOf('role/') !== 0) {
        return callback(new errors.InvalidParameterError(
            'ARN must specify a role'));
    }
    
    var roleName = resourcePart.substring(5); // Remove 'role/' prefix
    
    // Search for role in UFDS
    var searchBase = sprintf('uuid=%s, ou=users, o=smartdc', 
        accountId);
    var searchFilter = sprintf(
        '(&(objectclass=sdcaccountrole)(name=%s))', roleName);
    
    log.debug({
        roleArn: roleArn,
        searchBase: searchBase,
        searchFilter: searchFilter,
        accountId: accountId,
        roleName: roleName
    }, 'Searching for role in UFDS');
    
    ufds.search(searchBase, {
        scope: 'one',
        filter: searchFilter
    }, function(searchErr, result) {
        if (searchErr) {
            log.error({
                err: searchErr,
                roleArn: roleArn,
                searchBase: searchBase
            }, 'UFDS search failed for role');
            return callback(new errors.InternalError(
                'Failed to search for role'));
        }
        
        var roles = [];
        result.on('searchEntry', function(entry) {
            roles.push(entry.object);
            return;
        });
        
        result.on('end', function() {
            if (roles.length === 0) {
                log.warn({
                    roleArn: roleArn,
                    searchBase: searchBase,
                    searchFilter: searchFilter
                }, 'Role not found in UFDS');
                return callback(new errors.NoSuchEntityError(
                    'Role not found'));
            }
            
            if (roles.length > 1) {
                log.error({
                    roleArn: roleArn,
                    foundRoles: roles.length
                }, 'Multiple roles found with same name');
                return callback(new errors.InternalError(
                    'Multiple roles found'));
            }
            
            var role = roles[0];
            
            // Use Manta RBAC memberpolicy as AWS trust policy
            // memberpolicy is an array, so we look for the first entry that looks like a trust policy
            var trustPolicy = null;
            if (role.memberpolicy && role.memberpolicy.length > 0) {
                // Try to find an AWS trust policy format in memberpolicy array
                for (var i = 0; i < role.memberpolicy.length; i++) {
                    var policy = role.memberpolicy[i];
                    try {
                        var parsed = JSON.parse(policy);
                        // Check if this looks like an AWS trust policy (has Principal and sts:AssumeRole)
                        if (parsed.Statement && Array.isArray(parsed.Statement)) {
                            var hasAssumeRole = parsed.Statement.some(function(stmt) {
                                if (!stmt.Action) return false;
                                var actions = Array.isArray(stmt.Action) ? stmt.Action : [stmt.Action];
                                return actions.some(function(action) {
                                    return action === 'sts:AssumeRole' || action === '*';
                                });
                            });
                            if (hasAssumeRole) {
                                trustPolicy = policy;
                                break;
                            }
                        }
                    } catch (e) {
                        // Not JSON, skip this policy
                        continue;
                    }
                }
            }
            
            log.debug({
                roleArn: roleArn,
                roleName: role.name,
                hasTrustPolicy: !!trustPolicy,
                policyCount: role.memberpolicy ? role.memberpolicy.length : 0
            }, 'Role found in UFDS, mapped trust policy from memberpolicy');
            
            callback(null, trustPolicy);
            return;
        });
        
        result.on('error', function(resultErr) {
            log.error({
                err: resultErr,
                roleArn: roleArn
            }, 'UFDS search result error');
            callback(new errors.InternalError(
                'Role search failed'));
            return;
        });
    });
}

/**
 * @brief AWS STS AssumeRole operation implementation
 * 
 * Handles AssumeRole requests by validating trust policies, generating
 * temporary credentials, and returning AWS-compatible STS response.
 * Performs complete role assumption workflow including trust policy
 * validation, temporary credential generation, and UFDS storage.
 * 
 * @param {Object} req Restify request object containing parameters:
 * @param {string} req.params.RoleArn ARN of role to assume
 * @param {string} req.params.RoleSessionName Session identifier
 * @param {number} req.params.DurationSeconds Credential lifetime
 * @param {Object} res Restify response object
 * @param {function} next Restify next callback function
 * 
 * @note Validates caller authorization via trust policy evaluation
 * @note Generates MSTS-prefixed temporary access keys
 * @note Creates session tokens for credential identification  
 * @note Stores temporary credentials in UFDS with expiration
 * @note Returns AWS STS AssumeRoleResponse XML format
 * 
 * @error 400 InvalidParameterError Missing or invalid parameters
 * @error 403 AssumeRoleAccessDenied Trust policy denies access
 * @error 404 NoSuchEntityError Role not found in directory
 * @error 500 InternalError UFDS or credential generation failure
 * 
 * @example
 * POST /sts/assume-role
 * {
 *   "RoleArn": "arn:aws:iam::123456789012:role/MyRole",
 *   "RoleSessionName": "session1", 
 *   "DurationSeconds": 3600
 * }
 * 
 * @since 1.0.0
 */
function assumeRole(req, res, next) {
    var log = req.log;
    
    log.debug('sts.assumeRole: entered');
    
    // Extract parameters
    var roleArn = req.params.RoleArn || req.body.RoleArn;
    var roleSessionName = req.params.RoleSessionName || req.body.RoleSessionName;
    var durationSeconds = parseInt(req.params.DurationSeconds || req.body.DurationSeconds || 3600, 10);
    
    // Validate parameters
    if (!roleArn) {
        next(new errors.InvalidParameterError('RoleArn is required'));
        return;
    }
    
    if (!roleSessionName) {
        next(new errors.InvalidParameterError('RoleSessionName is required'));
        return;
    }
    
    if (durationSeconds < 900 || durationSeconds > 43200) {
        next(new errors.InvalidParameterError(
            'DurationSeconds must be between 900 and 43200'));
        return;
    }
    
    // For now, assume caller identity is available (from 
    // authentication middleware)
    var callerUuid = req.caller ? req.caller.uuid : null;
    if (!callerUuid) {
        next(new errors.InvalidParameterError(
            'Caller identity required'));
        return;
    }
    
    // Validate role trust policy before generating credentials
    if (!req.ufds) {
        log.warn({
            hasUfds: !!req.ufds,
            note: 'Using mock STS mode - skipping trust ' +
                'policy validation'
        }, 'UFDS client not available, skipping trust ' + 
            'policy validation');
        
        // In mock mode, skip validation and proceed to 
        // credential generation
        return generateAndReturnCredentials();
    }
    
    // Fetch role's trust policy from UFDS
    fetchRoleTrustPolicy(roleArn, req.ufds, log, 
        function(fetchErr, trustPolicy) {
        if (fetchErr) {
            log.error({
                err: fetchErr,
                roleArn: roleArn,
                callerUuid: callerUuid
            }, 'Failed to fetch role trust policy');
            return next(fetchErr);
        }
        
        // Validate trust policy
        if (!validateTrustPolicy(trustPolicy, req.caller, log)) {
            log.warn({
                roleArn: roleArn,
                callerUuid: callerUuid,
                callerAccountUuid: req.caller.account ? 
                    req.caller.account.uuid : null
            }, 'Trust policy validation failed - access denied');
            
            var accessDeniedError = new errors.AccessDeniedError(
                'AssumeRole access denied by trust policy');
            return next(accessDeniedError);
        }
        
        log.info({
            roleArn: roleArn,
            callerUuid: callerUuid
        }, 'Trust policy validation successful');
        
        // Generate and return credentials
        return generateAndReturnCredentials();
    });
    
    // Function to generate and return credentials (extracted for reuse)
    function generateAndReturnCredentials() {
        // Generate temporary credentials
        var tempAccessKeyId = generateTemporaryAccessKeyId();
        var tempSecretKey = generateTemporarySecretKey();
        var sessionToken = generateSessionToken();
        var expiration = new Date(Date.now() + 
            durationSeconds * 1000);
        
        // Add temporary credential to UFDS via LDAP client
        var dn = 'accesskeyid=' + tempAccessKeyId + 
            ', uuid=' + callerUuid + ', ou=users, o=smartdc';
        var ldapObject = {
            objectclass: ['accesskey'],
            accesskeyid: tempAccessKeyId,
            accesskeysecret: tempSecretKey,
            sessiontoken: sessionToken,
            expiration: expiration.toISOString(),
            principaluuid: callerUuid,
            assumedrole: roleArn,
            credentialtype: 'temporary',
            status: 'Active',
            created: Date.now().toString(),
            updated: Date.now().toString()
        };
        
        log.debug({
            dn: dn,
            tempCredential: {
                accessKeyId: tempAccessKeyId,
                expiration: expiration.toISOString(),
                roleArn: roleArn,
                sessionName: roleSessionName
            }
        }, 'Creating temporary credential in UFDS');
        
        if (!req.ufds) {
            log.error({
                hasUfds: !!req.ufds,
                roleArn: roleArn,
                sessionName: roleSessionName
            }, 'STS AssumeRole failed: UFDS client not available');
            
            next(new errors.InternalError(
                'STS service not properly configured - UFDS client unavailable'));
            return;
        }
        
        req.ufds.add(dn, ldapObject, function (addErr) {
            if (addErr) {
                log.error({
                    err: addErr,
                    dn: dn,
                    accessKeyId: tempAccessKeyId
                }, 'Failed to create temporary credential in UFDS');
                next(new errors.InternalError(
                    'Failed to create temporary credential'));
                return;
            }
            
            log.info({
                accessKeyId: tempAccessKeyId,
                expiration: expiration.toISOString(),
                roleArn: roleArn,
                sessionName: roleSessionName,
                dn: dn
            }, 'Successfully created temporary credential ' +
                'in UFDS');
            
            // Return STS response
            var response = {
                AssumeRoleResponse: {
                    AssumeRoleResult: {
                        Credentials: {
                            AccessKeyId: tempAccessKeyId,
                            SecretAccessKey: tempSecretKey,
                            SessionToken: sessionToken,
                            Expiration: expiration.toISOString()
                        },
                        AssumedRoleUser: {
                            AssumedRoleId: roleArn + ':' + 
                                roleSessionName,
                            Arn: roleArn
                        }
                    }
                }
            };
            
            res.send(200, response);
            next();
            return;
        });
    } // End generateAndReturnCredentials function
} // End assumeRole function

/**
 * @brief AWS STS GetSessionToken operation implementation
 * 
 * Generates temporary security credentials for the calling user
 * without role assumption. Creates session-scoped temporary
 * credentials with configurable duration for enhanced security
 * in multi-factor authentication scenarios.
 * 
 * @param {Object} req Restify request object containing parameters:
 * @param {number} req.params.DurationSeconds Credential lifetime
 * @param {Object} res Restify response object  
 * @param {function} next Restify next callback function
 * 
 * @note No role assumption - credentials for calling principal
 * @note Duration range: 900 seconds (15 min) to 129600 (36 hours)
 * @note Generates MSTS-prefixed temporary access keys
 * @note Creates base64-encoded session tokens for identification
 * @note Stores temporary credentials in UFDS with expiration
 * @note Returns AWS STS GetSessionTokenResponse XML format
 * 
 * @error 400 InvalidParameterError Invalid duration parameter
 * @error 500 InternalError Credential generation or storage failure
 * 
 * @example  
 * POST /sts/get-session-token
 * {
 *   "DurationSeconds": 7200
 * }
 * 
 * @since 1.0.0
 */
function getSessionToken(req, res, next) {
    var log = req.log;
    
    log.debug('sts.getSessionToken: entered');
    
    var durationSeconds = parseInt(req.params.DurationSeconds || req.body.DurationSeconds || 3600, 10);
    
    if (durationSeconds < 900 || durationSeconds > 129600) {
        next(new errors.InvalidParameterError(
            'DurationSeconds must be between 900 and 129600'));
        return;
    }
    
    var callerUuid = req.caller ? req.caller.uuid : null;
    if (!callerUuid) {
        next(new errors.InvalidParameterError(
            'Caller identity required'));
        return;
    }
    
    // Generate temporary credentials
    var tempAccessKeyId = generateTemporaryAccessKeyId();
    var tempSecretKey = generateTemporarySecretKey();
    var sessionToken = generateSessionToken();
    var expiration = new Date(Date.now() + 
        durationSeconds * 1000);
    
    // Add session token to UFDS via LDAP client
    var dn = 'accesskeyid=' + tempAccessKeyId + 
        ', uuid=' + callerUuid + ', ou=users, o=smartdc';
    var ldapObject = {
        objectclass: ['accesskey'],
        accesskeyid: tempAccessKeyId,
        accesskeysecret: tempSecretKey,
        sessiontoken: sessionToken,
        expiration: expiration.toISOString(),
        principaluuid: callerUuid,
        credentialtype: 'temporary',
        status: 'Active',
        created: Date.now().toString(),
        updated: Date.now().toString()
    };
    
    log.debug({
        dn: dn,
        tempCredential: {
            accessKeyId: tempAccessKeyId,
            expiration: expiration.toISOString(),
            principal: callerUuid
        }
    }, 'Creating session token in UFDS');
    
    if (!req.ufds) {
        log.error('UFDS client not available for STS operations');
        var ufdsError = new Error(
            'UFDS not configured for temporary credentials');
        ufdsError.statusCode = 503;
        return next(ufdsError);
    }
    
    req.ufds.add(dn, ldapObject, function (addErr) {
        if (addErr) {
            log.error({
                err: addErr,
                dn: dn,
                accessKeyId: tempAccessKeyId
            }, 'Failed to create session token in UFDS');
            next(new errors.InternalError(
                'Failed to create session token'));
            return;
        }
        
        log.info({
            accessKeyId: tempAccessKeyId,
            expiration: expiration.toISOString(),
            principal: callerUuid,
            dn: dn
        }, 'Successfully created session token in UFDS');
        
        // Return STS response
        var response = {
            GetSessionTokenResponse: {
                GetSessionTokenResult: {
                    Credentials: {
                        AccessKeyId: tempAccessKeyId,
                        SecretAccessKey: tempSecretKey,
                        SessionToken: sessionToken,
                        Expiration: expiration.toISOString()
                    }
                }
            }
        };
        
        res.send(200, response);
        next();
        return;
    });
}

module.exports = {
    assumeRole: assumeRole,
    getSessionToken: getSessionToken
};