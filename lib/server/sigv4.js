/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

var assert = require('assert-plus');
var crypto = require('crypto');
var sprintf = require('util').format;
var errors = require('./errors.js');
var utils = require('./utils.js');

/**
 * AWS SigV4 Authentication Module for Mahi
 */

/**
 * Parse AWS Authorization header
 * Format: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/
 * us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date,
 * Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024
 */
function parseAuthHeader(authHeader) {
        if (!authHeader || authHeader.indexOf('AWS4-HMAC-SHA256') !== 0) {
                return (null);
        }

    /* BEGIN JSSTYLED */
        var parts = authHeader.substring('AWS4-HMAC-SHA256 '.length)
                .split(/,\s*/);
    /* END JSSTYLED */
        var result = {};

        parts.forEach(function (part) {
                var keyValue = part.split('=');
                if (keyValue.length === 2) {
                        var key = keyValue[0];
                        var value = keyValue[1];

                        if (key === 'Credential') {
                                var credParts = value.split('/');
                                result.accessKeyId = credParts[0];
                                result.dateStamp = credParts[1];
                                result.region = credParts[2];
                                result.service = credParts[3];
                                result.requestType = credParts[4];
                        } else if (key === 'SignedHeaders') {
                                result.signedHeaders = value.split(';');
                        } else if (key === 'Signature') {
                                result.signature = value;
                        }
                }
        });

        return (result);
}

/**
 * Create canonical request string
 */
function encodeRfc3986(path) {
        return path.split('/').map(function (segment) {
                return encodeURIComponent(segment)
                        .replace(/[!'()*]/g, function (c) {
                                return '%' + c.charCodeAt(0).
                                        toString(16).toUpperCase();
                        });
        }).join('/');
}
function createCanonicalRequest(method, uri, queryString, headers,
        signedHeaders, payloadHash) {
        // Fix 1: Properly format query string according to AWS SigV4 spec
        var canonicalQueryString = '';
        if (queryString) {
                var params = queryString.split('&').map(function (param) {
                        var parts = param.split('=');
                        var key = encodeURIComponent(parts[0] || '');
                        // Handle empty values correctly - AWS SigV4 spec
                        // requires
                        // empty values to be encoded as empty string, not
                        // 'undefined'
                        var value = parts.length > 1 ?
                                encodeURIComponent(parts[1]) : '';
                        return (key + '=' + value);
                }).sort();
                canonicalQueryString = params.join('&');
        }
        var path = uri || '/';
        var canonicalURI = encodeRfc3986(path);
        // Fix 2: Sort signed headers
        // consistently (create copy to avoid mutation)
        var sortedSignedHeaders = signedHeaders.slice().sort();

        // Fix 3: Properly normalize header values according to AWS SigV4 spec
        var canonicalHeaders = '';

        // We send this from manta-buckets-api to match
        // the canonical url signature for sigv4 on clients
        // that create a signature using content-length
        // why we need this here? restify overwrites the real
        // content-length value, the same happens with content-md5
        //
        if ('content-length' in headers) {
            headers['content-length'] = headers['manta-s3-content-length'];
        }
        // Restify also overrides this header, so restoring the value here.
        if ('content-md5' in headers) {
            headers['content-md5'] = headers['manta-s3-content-md5'];
        }
        sortedSignedHeaders.forEach(function (name) {
                var value = headers[name.toLowerCase()] || '';
                // Collapse multiple spaces into single spaces and trim
                value = value.replace(/\s+/g, ' ').trim();
                canonicalHeaders += name.toLowerCase() + ':' + value + '\n';
        });

        var canonicalRequest = method + '\n' +
                               canonicalURI + '\n' +
                               canonicalQueryString + '\n' +
                               canonicalHeaders + '\n' +
                               sortedSignedHeaders.join(';') + '\n' +
                               payloadHash;

        return (canonicalRequest);
}

/**
 * Create string to sign
 */
function createStringToSign(timestamp, credentialScope, canonicalRequest) {
        var hashedCanonicalRequest = crypto.createHash('sha256')
                .update(canonicalRequest, 'utf8').digest('hex');

        return 'AWS4-HMAC-SHA256\n' +
                     timestamp + '\n' +
                     credentialScope + '\n' +
                     hashedCanonicalRequest;
}

/**
 * Calculate AWS4 signature
 */
function calculateSignature(secretKey, dateStamp, region, service,
        stringToSign) {
        function hmac(key, string) {
                return crypto.createHmac('sha256', key).update(string, 'utf8')
                        .digest();
        }
        var kDate = hmac('AWS4' + secretKey, dateStamp);
        var kRegion = hmac(kDate, region);
        var kService = hmac(kRegion, service);
        var kSigning = hmac(kService, 'aws4_request');
        return (hmac(kSigning, stringToSign).toString('hex'));
}

/**
 * @brief Handle temporary credential verification for STS
 * 
 * Verifies STS-issued temporary credentials by looking up the
 * access key in UFDS and validating session token, expiration,
 * and principal information.
 * 
 * @param authInfo Object containing accessKeyId and other auth data
 * @param sessionToken Session token from X-Amz-Security-Token header
 * @param req HTTP request object with Redis connection
 * @param log Bunyan logger instance for debug/error logging
 * @param ufds UFDS client instance for credential lookup
 * @param cb Callback function (err, result)
 * 
 * @returns Via callback: credential verification result with
 *          principal user data and role information
 * 
 * @note Validates credential expiration and session token match
 * @note Retrieves original principal user who assumed the role
 * @note Performs signature verification using temporary secret
 * 
 * @see AWS STS temporary credential documentation
 * @since 1.0.0
 */
function handleTemporaryCredential(authInfo, sessionToken, req, log, ufds, cb) {
    log.debug({
        accessKeyId: authInfo.accessKeyId,
        hasSessionToken: true
    }, 'sigv4.handleTemporaryCredential: looking up temporary credential');

    // Look up temporary credential in UFDS by access key ID
    var searchBase = 'ou=users, o=smartdc';
    var searchFilter = '(&(objectclass=accesskey)(accesskeyid=' + authInfo.accessKeyId + ')(credentialtype=temporary))';
    
    ufds.search(searchBase, {
        scope: 'sub',
        filter: searchFilter
    }, function (searchErr, searchRes) {
        if (searchErr) {
            log.error({
                err: searchErr,
                accessKeyId: authInfo.accessKeyId
            }, 'sigv4.handleTemporaryCredential: UFDS search failed');
            return cb(new errors.InvalidSignatureError('Failed to verify temporary credential'));
        }
        
        if (!searchRes || searchRes.length === 0) {
            log.warn({
                accessKeyId: authInfo.accessKeyId
            }, 'sigv4.handleTemporaryCredential: temporary credential not found');
            return cb(new errors.InvalidSignatureError('Invalid temporary access key'));
        }
        
        var tempCredential = searchRes[0];
        var credData = tempCredential.object || tempCredential;
        
        log.debug({
            accessKeyId: authInfo.accessKeyId,
            principalUuid: credData.principaluuid,
            assumedRole: credData.assumedrole,
            expiration: credData.expiration
        }, 'sigv4.handleTemporaryCredential: found temporary credential');
        
        // Check if credential has expired
        if (credData.expiration) {
            var expiration = new Date(credData.expiration);
            if (expiration < new Date()) {
                log.warn({
                    accessKeyId: authInfo.accessKeyId,
                    expiration: credData.expiration
                }, 'sigv4.handleTemporaryCredential: temporary credential expired');
                return cb(new errors.InvalidSignatureError('Temporary credential expired'));
            }
        }
        
        // Verify session token matches
        if (credData.sessiontoken !== sessionToken) {
            log.warn({
                accessKeyId: authInfo.accessKeyId
            }, 'sigv4.handleTemporaryCredential: session token mismatch');
            return cb(new errors.InvalidSignatureError('Invalid session token'));
        }
        
        // Get the principal user data (the original user who assumed the role)  
        var principalUuid = credData.principaluuid;
        var redis = req.redis;
        var userKey = sprintf('/uuid/%s', principalUuid);
        
        redis.get(userKey, function (err, userRes) {
            if (err || !userRes) {
                log.error({
                    err: err,
                    principalUuid: principalUuid
                }, 'sigv4.handleTemporaryCredential: failed to get principal user');
                return cb(new errors.InvalidSignatureError('Invalid principal user'));
            }
            
            var user = JSON.parse(userRes);
            
            // Verify signature using the temporary credential's secret key
            var secretKey = credData.accesskeysecret;
            
            // Perform signature verification (reuse permanent credential logic)
            var timestamp = req.headers['x-amz-date'];
            if (!timestamp) {
                return cb(new errors.InvalidSignatureError('Missing X-Amz-Date header'));
            }
            
            // Check timestamp skew (15 minutes threshold)
            var requestTime = new Date(timestamp).getTime();
            var currentTime = Date.now();
            var timeDiff = Math.abs(currentTime - requestTime);
            
            if (timeDiff > 15 * 60 * 1000) { // 15 minutes
                return cb(new errors.InvalidSignatureError('Request timestamp too old'));
            }
            
            // Build canonical request using original request data
            var originalMethod = req.query.method || req.method;
            var originalUrl = req.query.url || req.url;
            
            var uri = originalUrl.split('?')[0];
            if (req.query.url) {
                originalUrl = decodeURIComponent(originalUrl);
                uri = decodeURIComponent(uri);
            }
            
            var queryString = originalUrl.split('?')[1] || '';
            
            // Remove sessionToken from query string for signature verification
            // The sessionToken was added by buckets-api after AWS CLI signed the request
            if (queryString) {
                queryString = queryString.replace(/[&?]?sessionToken=[^&]*&?/g, '')
                    .replace(/^&/, '').replace(/&$/, '');
            }
            
            var payloadHash = req.headers['x-amz-content-sha256'] || 'UNSIGNED-PAYLOAD';
            
            var canonicalRequest = createCanonicalRequest(
                originalMethod, uri, queryString, req.headers,
                authInfo.signedHeaders, payloadHash);
            
            // Create string to sign
            var credentialScope = sprintf('%s/%s/%s/aws4_request',
                authInfo.dateStamp, authInfo.region, authInfo.service);
            var stringToSign = createStringToSign(timestamp, credentialScope, canonicalRequest);
            
            log.debug({
                originalMethod: originalMethod,
                uri: uri,
                queryString: queryString,
                signedHeaders: authInfo.signedHeaders,
                payloadHash: payloadHash,
                credentialScope: credentialScope,
                canonicalRequest: canonicalRequest,
                stringToSign: stringToSign,
                secretKey: secretKey.substring(0, 10) + '...'
            }, 'sigv4.handleTemporaryCredential: signature calculation details');
            
            // Calculate expected signature using temporary secret key
            var expectedSignature = calculateSignature(secretKey, authInfo.dateStamp,
                authInfo.region, authInfo.service, stringToSign);
            
            // Verify signature matches
            if (expectedSignature !== authInfo.signature) {
                log.warn({
                    accessKeyId: authInfo.accessKeyId,
                    expectedSignature: expectedSignature,
                    providedSignature: authInfo.signature
                }, 'sigv4.handleTemporaryCredential: signature mismatch for temporary credential');
                return cb(new errors.InvalidSignatureError('Signature mismatch'));
            }
            
            log.debug({
                accessKeyId: authInfo.accessKeyId,
                principalUuid: principalUuid,
                assumedRole: credData.assumedrole
            }, 'sigv4.handleTemporaryCredential: signature verification successful');
            
            // Return result with role information
            cb(null, {
                user: user,
                accessKeyId: authInfo.accessKeyId,
                userUuid: principalUuid,
                valid: true,
                // Additional fields for role-based access
                isTemporaryCredential: true,
                assumedRole: credData.assumedrole,
                principalUuid: principalUuid,
                credentialType: 'temporary'
            });
            return;
        });
        return;
    });
}

/**
 * Verify AWS SigV4 signature (supports both permanent and temporary credentials)
 */
function verifySigV4(opts, cb) {
        assert.object(opts, 'opts');
        assert.object(opts.req, 'opts.req');
        assert.object(opts.log, 'opts.log');
        assert.object(opts.redis, 'opts.redis');
        assert.func(cb, 'callback');

        var req = opts.req;
        var log = opts.log;
        var redis = opts.redis;
        var ufds = opts.ufds; // UFDS client for temporary credential lookup

        log.debug('sigv4.verify: entered');

        var authHeader = req.headers.authorization;
        if (!authHeader) {
                setImmediate(cb, new errors.InvalidSignatureError(
                        'Missing Authorization header'));
                return;
        }

        var authInfo = parseAuthHeader(authHeader);
        if (!authInfo) {
                setImmediate(cb, new errors.InvalidSignatureError(
                        'Invalid Authorization header format'));
                return;
        }

        // Debug: Log the parsed authorization info
        log.debug({
                authHeader: authHeader,
                parsedAuthInfo: authInfo,
                accessKeyId: authInfo.accessKeyId,
                accessKeyIdLength: authInfo.accessKeyId ?
                        authInfo.accessKeyId.length : 0,
                accessKeyIdHex: (authInfo.accessKeyId &&
                                 typeof (authInfo.accessKeyId) === 'string') ?
                     new Buffer(authInfo.accessKeyId).toString('hex') :
                        null,
                userAgent: req.headers['user-agent']
        }, 'Authorization header debug');

        // Check if this is a temporary credential request (has sessionToken parameter)
        // The session token can be in req.query.sessionToken or embedded in the URL
        var sessionToken = req.query.sessionToken;
        
        // If not in query, check if it's embedded in the URL parameter
        if (!sessionToken && req.query.url) {
            var urlMatch = req.query.url.match(/sessionToken=([^&]+)/);
            if (urlMatch) {
                sessionToken = decodeURIComponent(urlMatch[1]);
            }
        }
        
        var isTemporaryCredential = sessionToken && typeof sessionToken === 'string' && sessionToken.length > 10;
        
        log.info({
            hasSessionToken: !!sessionToken,
            isTemporaryCredential: isTemporaryCredential,
            accessKeyId: authInfo.accessKeyId,
            hasUfds: !!ufds,
            queryParams: Object.keys(req.query || {}),
            sessionTokenLength: sessionToken ? sessionToken.length : 0,
            fullQueryObject: req.query,
            urlParam: req.query ? req.query.url : 'no-url-param',
            sessionTokenSource: sessionToken ? (req.query.sessionToken ? 'direct-query' : 'url-embedded') : 'not-found'
        }, 'sigv4.verify: CREDENTIAL TYPE DETECTION');

        if (isTemporaryCredential && ufds) {
            log.info({
                accessKeyId: authInfo.accessKeyId,
                sessionToken: sessionToken.substring(0, 20) + '...'
            }, 'sigv4.verify: ROUTING TO TEMPORARY CREDENTIAL HANDLER');
            // Handle temporary credentials - look up from UFDS
            return handleTemporaryCredential(authInfo, sessionToken, req, log, ufds, cb);
        }
        
        if (isTemporaryCredential && !ufds) {
            log.error('sigv4.verify: TEMPORARY CREDENTIAL DETECTED BUT NO UFDS CLIENT AVAILABLE');
            return cb(new errors.InvalidSignatureError('Cannot verify temporary credentials'));
        }

        // Handle permanent credentials - look up from Redis
        // Look up user by access key ID
        var accessKeyLookupKey = sprintf('/accesskey/%s',
                authInfo.accessKeyId);
        redis.get(accessKeyLookupKey, function (err, userUuid) {
                if (err) {
                        cb(new errors.RedisError(err));
                        return;
                }

                if (!userUuid) {
                        cb(new errors.InvalidSignatureError(
                                'Invalid access key'));
                        return;
                }

                // Get user's access keys
                var userKey = sprintf('/uuid/%s', userUuid);
                redis.get(userKey, function (err, userRes) {
                        if (err) {
                                cb(new errors.RedisError(err));
                                return;
                        }

                        if (!userRes) {
                                cb(new errors.InvalidSignatureError(
                                        'User not found'));
                                return;
                        }

                        var user = JSON.parse(userRes);
                        if (!user.accesskeys ||
                                !user.accesskeys[authInfo.accessKeyId]) {
                                cb(new errors.InvalidSignatureError(
                                        'Access key not found'));
                                return;
                        }

                        var secretKey = user.accesskeys[authInfo.accessKeyId];
                        var timestamp = req.headers['x-amz-date'] ||
                                req.headers.date;
                        if (!timestamp) {
                                cb(new errors.InvalidSignatureError(
                                        'Missing timestamp'));
                                return;
                        }

                        // According to AWS S3 documentation a 15 minutes
                        // threshold is used as a security mechanism to
                        // prevent replay attacks.
                        // https://docs.aws.amazon.com/AmazonS3/latest/API/\
                        // sig-v4-authenticating-requests.html
                        var requestTime = new Date(timestamp).getTime();
                        var currentTime = Date.now();
                        var timeDiff = Math.abs(currentTime - requestTime);

                        if (timeDiff > 15 * 60 * 1000) { // 15 minutes
                                cb(new errors.InvalidSignatureError(
                                        'Request timestamp too old'));
                                return;
                        }

                        // Build canonical request using original request data
                        // from query params.
                        // The original method and URL are passed as query
                        // parameters to /aws-verify
                        var originalMethod = req.query.method || req.method;
                        var originalUrl = req.query.url || req.url;
                        // URL decode the originalUrl if it comes from query
                        // params (fixes Cyberduck compatibility without
                        // affecting AWS CLI)

                        var uri = originalUrl.split('?')[0];
                        if (req.query.url) {
                                originalUrl = decodeURIComponent(originalUrl);
                                uri = decodeURIComponent(uri);
                        }

                        var queryString = originalUrl.split('?')[1] || '';
                        var payloadHash = req.headers['x-amz-content-sha256'] ||
                                'UNSIGNED-PAYLOAD';

                        var canonicalRequest = createCanonicalRequest(
                                originalMethod, uri, queryString, req.headers,
                                authInfo.signedHeaders, payloadHash);

                        // Print hexdump of canonicalRequest
                        log.debug('canonicalRequest hexdump:\n'+
                            utils.hexdump(canonicalRequest));

                        // Create string to sign
                        var credentialScope = sprintf('%s/%s/%s/aws4_request',
                                authInfo.dateStamp, authInfo.region,
                                authInfo.service);
                        var stringToSign = createStringToSign(timestamp,
                                credentialScope, canonicalRequest);

                        log.debug('stringToSign hexdump:\n'+
                            utils.hexdump(stringToSign));

                        // Calculate expected signature
                        var expectedSignature = calculateSignature(
                                secretKey, authInfo.dateStamp, authInfo.region,
                                authInfo.service, stringToSign);

                        // Compare signatures
                        if (expectedSignature !== authInfo.signature) {
                                log.debug({
                                        expected: expectedSignature,
                                        received: authInfo.signature,
                                        stringToSign: stringToSign,
                                        canonicalRequest: canonicalRequest
                                }, 'Signature mismatch');
                                cb(new errors.InvalidSignatureError(
                                        'Signature mismatch'));
                                return;
                        }

                        log.debug({accessKeyId: authInfo.accessKeyId,
                                userUuid: userUuid},
                                'SigV4 verification successful');
                        cb(null, {
                                user: user,
                                accessKeyId: authInfo.accessKeyId
                        });
                        return;
                });
                return;
        });
}

module.exports = {
        parseAuthHeader: parseAuthHeader,
        verifySigV4: verifySigV4
};
