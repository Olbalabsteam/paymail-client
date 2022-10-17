import { brfc } from 'brfc';
import AbortController from 'abort-controller';
import PureCache from 'pure-cache';
import moment from 'moment';
import fetch from 'node-fetch';
import HttpStatus from 'http-status-codes';

const CapabilityCodes = {
  pki: "pki",
  paymentDestination: "paymentDestination",
  requestSenderValidation: brfc("bsvalias Payment Addressing (Payer Validation)", ["andy (nChain)"], ""),
  verifyPublicKeyOwner: brfc("bsvalias public key verify (Verify Public Key Owner)", [], ""),
  publicProfile: brfc("Public Profile (Name & Avatar)", ["Ryan X. Charles (Money Button)"], "1"),
  receiveTransaction: brfc("Send raw transaction", ["Miguel Duarte (Money Button)", "Ryan X. Charles (Money Button)", "Ivan Mlinaric (Handcash)", "Rafa (Handcash)"], "1.1"),
  p2pPaymentDestination: brfc("Get no monitored payment destination (p2p payment destination)", ["Miguel Duarte (Money Button)", "Ryan X. Charles (Money Button)", "Ivan Mlinaric (Handcash)", "Rafa (Handcash)"], "1.1"),
  assetInformation: brfc("Asset Information", ["Fabriik"], "1"),
  p2pPaymentDestinationWithTokensSupport: brfc("P2P Payment Destination with Tokens Support", ["Fabriik"], "1"),
  sfpBuildAction: brfc("Simple Fabriik Protocol for Tokens Build Action", ["Fabriik"], "1"),
  sfpAuthoriseAction: brfc("Simple Fabriik Protocol for Tokens Authorise Action", ["Fabriik"], "1")
};

class PaymailServerError extends Error {}

// import { DnsOverHttps } from "./dns-over-https"
class DnsClient {
  constructor(dns, doh) {
    this.dns = dns;
    this.doh = doh;
  }
  async checkSrv(aDomain) {
    return new Promise((resolve, reject) => {
      this.dns.resolveSrv(`_bsvalias._tcp.${aDomain}`, async (err, result) => {
        try {
          if (err && (err.code === 'ENODATA' || err.code === 'ENOTFOUND')) {
            return resolve({
              domain: aDomain,
              port: 443,
              isSecure: true
            });
          }
          if (err) {
            return reject(err);
          }
          const {
            name: domainFromDns,
            port,
            isSecure
          } = result[0];
          resolve({
            domain: domainFromDns,
            port,
            isSecure: this.checkDomainIsSecure(domainFromDns, aDomain) || isSecure
          });
        } catch (err) {
          return reject(err);
        }
      });
    }).then(result => {
      if (result.isSecure) {
        return result;
      } else {
        return this.validateDnssec(aDomain);
      }
    }, err => {
      console.error(err);
      return err;
    });
  }
  checkDomainIsSecure(srvResponseDomain, originalDomain) {
    if (this.domainsAreEqual(srvResponseDomain, originalDomain)) {
      return true;
    } else if (this.responseIsWwwSubdomain(srvResponseDomain, originalDomain)) {
      return true;
    } else if (this.isHandcashDomain(originalDomain)) {
      // tell rafa to fix handcash and we can remove the special case :)
      return this.domainsAreEqual('handcash-paymail-production.herokuapp.com', srvResponseDomain) || this.domainsAreEqual('handcash-cloud-production.herokuapp.com', srvResponseDomain);
    } else if (this.isHandcashInternalDomain(originalDomain)) {
      return this.domainsAreEqual('handcash-cloud-staging.herokuapp.com', srvResponseDomain);
    } else if (this.domainsAreEqual('localhost', srvResponseDomain)) {
      return true;
    } else if (this.isMoneyButtonDomain(srvResponseDomain)) {
      return true;
    } else {
      return false;
    }
  }
  isMoneyButtonDomain(aDomain) {
    return this.domainsAreEqual(aDomain, 'moneybutton.com') || this.domainsAreEqual(aDomain, 'www.moneybutton.com');
  }
  responseIsWwwSubdomain(srvResponseDomain, originalDomain) {
    return this.domainsAreEqual(srvResponseDomain, `www.${originalDomain}`);
  }
  isHandcashDomain(aDomain) {
    return this.domainsAreEqual('handcash.io', aDomain);
  }
  isHandcashInternalDomain(aDomain) {
    return this.domainsAreEqual('internal.handcash.io', aDomain);
  }
  async validateDnssec(aDomain) {
    const dnsResponse = await this.doh.queryBsvaliasDomain(aDomain);
    if (dnsResponse.Status !== 0 || !dnsResponse.Answer) {
      throw new PaymailServerError(`${aDomain} is not correctly configured: insecure domain`);
    }
    const data = dnsResponse.Answer[0].data.split(' ');
    const port = data[2];
    const responseDomain = data[3];
    if (!dnsResponse.AD && !this.domainsAreEqual(aDomain, responseDomain)) {
      throw new PaymailServerError(`${aDomain} is not correctly configured: insecure domain`);
    }
    return {
      port,
      domain: responseDomain,
      isSecure: dnsResponse.AD
    };
  }
  domainsAreEqual(domain1, domain2) {
    return domain1.replace(/\.$/, '') === domain2.replace(/\.$/, '');
  }
}

class DnsOverHttps {
  constructor(fetch, config) {
    this.fetch = fetch;
    this.config = config;
  }
  async resolveSrv(aDomain) {
    const response = await this.fetch(`${this.config.baseUrl}?name=${aDomain}&type=SRV&cd=0`);
    const body = await response.json();
    return body;
  }
  async queryBsvaliasDomain(aDomain) {
    return this.resolveSrv(`_bsvalias._tcp.${aDomain}`);
  }
}

function ownKeys(object, enumerableOnly) {
  var keys = Object.keys(object);
  if (Object.getOwnPropertySymbols) {
    var symbols = Object.getOwnPropertySymbols(object);
    enumerableOnly && (symbols = symbols.filter(function (sym) {
      return Object.getOwnPropertyDescriptor(object, sym).enumerable;
    })), keys.push.apply(keys, symbols);
  }
  return keys;
}
function _objectSpread2(target) {
  for (var i = 1; i < arguments.length; i++) {
    var source = null != arguments[i] ? arguments[i] : {};
    i % 2 ? ownKeys(Object(source), !0).forEach(function (key) {
      _defineProperty(target, key, source[key]);
    }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)) : ownKeys(Object(source)).forEach(function (key) {
      Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key));
    });
  }
  return target;
}
function _defineProperty(obj, key, value) {
  if (key in obj) {
    Object.defineProperty(obj, key, {
      value: value,
      enumerable: true,
      configurable: true,
      writable: true
    });
  } else {
    obj[key] = value;
  }
  return obj;
}

class Http {
  constructor(fetch) {
    this.fetch = fetch;
  }
  async get(url) {
    return this._basicRequest(url);
  }
  async postJson(url, body) {
    return this._basicRequest(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    });
  }
  async _basicRequest(url, options = {}) {
    var controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    return this.fetch(url, _objectSpread2({}, options, {
      credentials: 'omit',
      signal: controller.signal
    })).then(result => {
      clearTimeout(timer);
      return result;
    });
  }
}

class EndpointResolver {
  constructor(dns = null, fetch, defaultCacheTTL = 0) {
    this.dnsClient = new DnsClient(dns, new DnsOverHttps(fetch, {
      baseUrl: 'https://dns.google.com/resolve'
    }));
    this.http = new Http(fetch);
    this.defaultCacheTTL = defaultCacheTTL;
    if (defaultCacheTTL) {
      this.cache = new PureCache({
        expiryCheckInterval: 10000
      });
      if (this.cache.cacheExpirer.timer.unref) {
        this.cache.cacheExpirer.timer.unref();
      }
    }
  }
  static create(dnsClient, fetch) {
    const instance = new EndpointResolver(null, fetch);
    instance.dnsClient = dnsClient;
    return instance;
  }
  async getIdentityUrlFor(aPaymail) {
    const [alias, domain] = aPaymail.split('@');
    await this.ensureCapabilityFor(domain, CapabilityCodes.pki);
    const apiDescriptor = await this.getApiDescriptionFor(domain);
    const identityUrl = apiDescriptor.capabilities.pki.replace('{alias}', alias).replace('{domain.tld}', domain);
    return identityUrl;
  }
  async getAddressUrlFor(aPaymail) {
    const [alias, domain] = aPaymail.split('@');
    await this.ensureCapabilityFor(domain, CapabilityCodes.paymentDestination);
    const apiDescriptor = await this.getApiDescriptionFor(domain);
    const addressUrl = apiDescriptor.capabilities.paymentDestination.replace('{alias}', alias).replace('{domain.tld}', domain);
    return addressUrl;
  }
  async getVerifyUrlFor(aPaymail, aPubkey) {
    const [alias, domain] = aPaymail.split('@');
    await this.ensureCapabilityFor(domain, CapabilityCodes.verifyPublicKeyOwner);
    const apiDescriptor = await this.getApiDescriptionFor(domain);
    const url = apiDescriptor.capabilities[CapabilityCodes.verifyPublicKeyOwner].replace('{alias}', alias).replace('{domain.tld}', domain).replace('{pubkey}', aPubkey);
    return url;
  }
  async getPublicProfileUrlFor(aPaymail) {
    const [alias, domain] = aPaymail.split('@');
    await this.ensureCapabilityFor(domain, CapabilityCodes.publicProfile);
    const apiDescriptor = await this.getApiDescriptionFor(domain);
    const url = apiDescriptor.capabilities[CapabilityCodes.publicProfile].replace('{alias}', alias).replace('{domain.tld}', domain);
    return url;
  }
  async getSendTxUrlFor(aPaymail) {
    const [alias, domain] = aPaymail.split('@');
    await this.ensureCapabilityFor(domain, CapabilityCodes.receiveTransaction);
    const apiDescriptor = await this.getApiDescriptionFor(domain);
    const url = apiDescriptor.capabilities[CapabilityCodes.receiveTransaction].replace('{alias}', alias).replace('{domain.tld}', domain);
    return url;
  }
  async getP2pPaymentDestinationUrlFor(aPaymail) {
    const [alias, domain] = aPaymail.split('@');
    await this.ensureCapabilityFor(domain, CapabilityCodes.p2pPaymentDestination);
    const apiDescriptor = await this.getApiDescriptionFor(domain);
    const url = apiDescriptor.capabilities[CapabilityCodes.p2pPaymentDestination].replace('{alias}', alias).replace('{domain.tld}', domain);
    return url;
  }
  async getP2pPaymentDestinationWithTokensSupportUrlFor(aPaymail) {
    const [alias, domain] = aPaymail.split('@');
    await this.ensureCapabilityFor(domain, CapabilityCodes.p2pPaymentDestinationWithTokensSupport);
    const apiDescriptor = await this.getApiDescriptionFor(domain);
    const url = apiDescriptor.capabilities[CapabilityCodes.p2pPaymentDestinationWithTokensSupport].replace('{alias}', alias).replace('{domain.tld}', domain);
    return url;
  }
  async getSfpBuildActionUrlFor(aPaymail) {
    const [, domain] = aPaymail.split('@');
    await this.ensureCapabilityFor(domain, CapabilityCodes.sfpBuildAction);
    const apiDescriptor = await this.getApiDescriptionFor(domain);
    const url = apiDescriptor.capabilities[CapabilityCodes.sfpBuildAction];
    return url;
  }
  async getSfpAuthoriseActionUrlFor(aPaymail) {
    const [, domain] = aPaymail.split('@');
    await this.ensureCapabilityFor(domain, CapabilityCodes.sfpAuthoriseAction);
    const apiDescriptor = await this.getApiDescriptionFor(domain);
    const url = apiDescriptor.capabilities[CapabilityCodes.sfpAuthoriseAction];
    return url;
  }
  async getAssetInformationUrlFor(aPaymail) {
    const [alias, domain] = aPaymail.split('@');
    await this.ensureCapabilityFor(domain, CapabilityCodes.assetInformation);
    const apiDescriptor = await this.getApiDescriptionFor(domain);
    const url = apiDescriptor.capabilities[CapabilityCodes.assetInformation].replace('{alias}', alias).replace('{domain.tld}', domain);
    return url;
  }
  async domainHasCapability(aDomain, capability) {
    const apiDescriptor = await this.getApiDescriptionFor(aDomain);
    return apiDescriptor.capabilities && !!apiDescriptor.capabilities[capability];
  }
  async getApiDescriptionFor(aDomain) {
    let apiDescriptor = this.cache && this.cache.get(aDomain);
    if (apiDescriptor) {
      return apiDescriptor.value;
    }
    const {
      domain,
      port
    } = await this.getWellKnownBaseUrl(aDomain);
    apiDescriptor = await this.fetchApiDescriptor(domain, port);
    this.cache && this.cache.put(aDomain, apiDescriptor, this.defaultCacheTTL);
    return apiDescriptor;
  }
  async fetchApiDescriptor(domain, port) {
    const protocol = domain === 'localhost' || domain === 'localhost.' ? 'http' : 'https';
    const requestPort = port.toString() === '443' ? '' : `:${port}`;
    const requestDomain = /^(.*?)\.?$/.exec(domain)[1]; // Get value from capture group
    if (!requestDomain) {
      throw new Error(`Invalid domain: ${domain}`);
    }
    try {
      const wellKnown = await this.http.get(`${protocol}://${requestDomain}${requestPort}/.well-known/bsvalias`);
      const apiDescriptor = await wellKnown.json();
      return apiDescriptor;
    } catch (err) {
      if (err.message.includes('invalid json response') || err.message.includes('Unexpected token')) {
        throw new PaymailServerError(`Paymail server at ${domain} returned an invalid capabilities description`);
      }
      if (err.message.includes('getaddrinfo ENOTFOUND')) {
        throw new PaymailServerError(`Couldn't find domain ${domain}`);
      }
      if (err.message.includes('failed')) {
        throw new PaymailServerError(`Couldn't connect to domain ${domain}`);
      }
      throw err;
    }
  }
  async getWellKnownBaseUrl(aDomain) {
    return this.dnsClient.checkSrv(aDomain);
  }
  async ensureCapabilityFor(aDomain, aCapability) {
    if (!(await this.domainHasCapability(aDomain, aCapability))) {
      throw new Error(`Unknown capability "${aCapability}" for "${aDomain}"`);
    }
  }
}

class VerifiableMessage {
  constructor(parts, bsv = null) {
    if (bsv === null) {
      bsv = require('bsv');
    }
    this.bsv = bsv;
    this.concatenated = Buffer.from(parts.join(''));
  }
  static forBasicAddressResolution({
    senderHandle,
    amount,
    dt,
    purpose
  }) {
    if (dt.toISOString) {
      dt = dt.toISOString();
    }
    return new VerifiableMessage([senderHandle, amount || '0', dt, purpose]);
  }
  sign(wifPrivKey) {
    let privKey = this.bsv.PrivKey.fromWif(wifPrivKey);
    let keyPair = this.bsv.KeyPair.fromPrivKey(privKey);
    return this.bsv.Bsm.sign(this.concatenated, keyPair);
  }
  verify(keyAddress, signature) {
    return this.bsv.Bsm.verify(this.concatenated, signature, this.bsv.Address.fromString(keyAddress));
  }
}

class RequestBodyFactory {
  constructor(clock) {
    this.clock = clock;
  }
  buildBodyToRequestAddress(senderInfo, privateKey = null) {
    const {
      senderHandle,
      amount,
      senderName,
      purpose,
      pubkey,
      signature: providedSignature
    } = senderInfo;
    if (!providedSignature && privateKey === null) {
      throw new Error('Missing private key or signature');
    }
    let dt, signature;
    if (providedSignature) {
      if (!senderInfo.dt) {
        throw new Error('missing datetime for given signature');
      }
      dt = senderInfo.dt;
      signature = providedSignature;
    } else {
      dt = this.clock.now();
      signature = VerifiableMessage.forBasicAddressResolution({
        senderHandle,
        amount,
        dt,
        purpose
      }).sign(privateKey);
    }
    return {
      senderHandle,
      senderName,
      purpose,
      dt,
      amount: amount || null,
      pubkey,
      signature
    };
  }
  buildBodySendTx(hexTransaction, reference, metadata) {
    return {
      hex: hexTransaction,
      metadata,
      reference
    };
  }
  buildBodyP2pPaymentDestination(satoshis) {
    return {
      satoshis
    };
  }
}

class Clock {
  now() {
    return moment();
  }
}

class PaymailNotFound extends Error {
  constructor(message, paymail) {
    super(message);
    this.paymail = paymail;
  }
}

class BrowserDns {
  constructor(fetch) {
    this.doh = new DnsOverHttps(fetch, {
      baseUrl: 'https://dns.google.com/resolve'
    });
  }
  async resolveSrv(aDomain, aCallback) {
    try {
      const response = await this.doh.resolveSrv(aDomain);
      if (response.Status === 0 && response.Answer) {
        const data = response.Answer.map(record => {
          const [priority, weight, port, name] = record.data.split(' ');
          return {
            priority,
            weight,
            port,
            name,
            isSecure: response.AD
          };
        });
        aCallback(null, data);
      } else if (response.Status === 3 || !response.Answer) {
        aCallback({
          code: 'ENODATA'
        });
      } else {
        aCallback(new Error('error during dns query'));
      }
    } catch (e) {
      aCallback(e);
    }
  }
}

class ProtocolNotSupported extends Error {
  constructor(message, protocol) {
    super(message);
    this.protocol = protocol;
  }
}

class AssetNotAccepted extends Error {
  constructor(message, asset) {
    super(message);
    this.asset = asset;
  }
}

class PaymailClient {
  constructor(dns = null, fetch2 = null, clock = null, bsv = null) {
    let defaultCacheTTL = 3600 * 1000;
    if (fetch2 === null) {
      fetch2 = fetch;
    }
    if (dns === null) {
      dns = new BrowserDns(fetch2);
      defaultCacheTTL = 0;
    }
    if (bsv === null) {
      bsv = require("bsv");
    }
    this.bsv = bsv;
    this.resolver = new EndpointResolver(dns, fetch2, defaultCacheTTL);
    this.http = new Http(fetch2);
    this.requestBodyFactory = new RequestBodyFactory(clock !== null ? clock : new Clock());
    this.VerifiableMessage = VerifiableMessage;
  }

  /**
   * Uses pki flow to query for an identity key for a given paymail address.
   *
   * @param {String} paymail - a paymail address
   */
  async getPublicKey(paymail) {
    const identityUrl = await this.resolver.getIdentityUrlFor(paymail);
    const response = await this.http.get(identityUrl);
    const {
      pubkey
    } = await response.json();
    return pubkey;
  }

  /**
   * Uses `Basic Address Resolution` flow to query for a payment for output for the
   * given paymail address.
   *
   * @param {String} aPaymail - a paymail address
   * @param {Object} senderInfo - Object containing sender info
   * @param {String} senderInfo.senderHandle - Sender paymail address
   * @param {String} senderInfo.amount - Optional. Required amount.
   * @param {String} senderInfo.senderName - Optional. Sender name.
   * @param {String} senderInfo.purpose - Optional. Purpose of the payment.
   * @param {String} senderInfo.pubkey - Optional. Public key used to sign the message.
   * @param {String} senderInfo.signature - Optional. Valid signature according to paymail specification.
   * @param {String} privateKey - Optional. private key to sign the request.
   */
  async getOutputFor(aPaymail, senderInfo, privateKey = null) {
    const addressUrl = await this.resolver.getAddressUrlFor(aPaymail);
    const body = this.requestBodyFactory.buildBodyToRequestAddress(senderInfo, privateKey);
    const response = await this.http.postJson(addressUrl, body);
    if (response.status === HttpStatus.NOT_FOUND) {
      throw new PaymailNotFound(`Paymail not found: ${aPaymail}`, aPaymail);
    } else if (!response.ok) {
      throw new Error(`Server failed with: ${await response.text()}`);
    }
    const {
      output
    } = await response.json();
    return output;
  }

  /**
   * Verify if the given public address belongs to the given
   * paymail address.
   *
   * @param {String} pubkey - Public key to check.
   * @param {String} paymail - a paymail address
   */
  async verifyPubkeyOwner(pubkey, paymail) {
    const url = await this.resolver.getVerifyUrlFor(paymail, pubkey);
    const response = await this.http.get(url);
    const body = await response.json();
    const {
      match
    } = body;
    return match;
  }

  /**
   * Verifies if a given signature is valid for a given message. It uses
   * different strategies depending on the capabilities of the server
   * and the parameters Given. The priority order is.
   * - If paymail is not provided, then normal signature verification is performed.
   * - Use provided key (and check that belongs to given paymail address).
   * - Get a new pubkey for given paymail address using pki.
   * - If there is no way to intereact with the owner of the domain to verify the public key it returns false.
   *
   * @param {Message} message - Message to verify
   * @param {String} signature - Signature
   * @param {String} paymail - Signature owner paymail
   * @param {String} pubkey - Optional. Public key that validates the signature.
   */
  async isValidSignature(message, signature, paymail = null, pubkey = null) {
    if (paymail == null && pubkey === null) {
      throw new Error("Must specify either paymail or pubkey");
    }
    let senderPubKey;
    if (paymail) {
      if (pubkey && (await this.resolver.domainHasCapability(paymail.split("@")[1], CapabilityCodes.verifyPublicKeyOwner))) {
        if (await this.verifyPubkeyOwner(pubkey, paymail)) {
          senderPubKey = this.bsv.PubKey.fromString(pubkey);
        } else {
          return false;
        }
      } else {
        const hasPki = await this.resolver.domainHasCapability(paymail.split("@")[1], CapabilityCodes.pki);
        if (hasPki) {
          const identityKey = await this.getPublicKey(paymail);
          senderPubKey = this.bsv.PubKey.fromString(identityKey);
        } else {
          return false;
        }
      }
    }
    const senderKeyAddress = this.bsv.Address.fromPubKey(senderPubKey || pubkey);
    try {
      const verified = message.verify(senderKeyAddress.toString(), signature);
      return verified;
    } catch (err) {
      // console.log(err)
      return false;
    }
  }

  /**
   * Gets the public profile information using the "Public Profile" protocol.
   *
   * @param {String} paymail - a paymail address
   * @param {String} s - the preferred size of the image
   */
  async getPublicProfile(paymail) {
    let publicProfileUrl = await this.resolver.getPublicProfileUrlFor(paymail);
    const response = await this.http.get(publicProfileUrl);
    if (!response.ok) {
      const body = await response.json();
      throw new Error(`Server failed with: ${JSON.stringify(body)}`);
    }
    const {
      avatar,
      name
    } = await response.json();
    return {
      avatar,
      name
    };
  }
  async sendRawTx(targetPaymail, hexTransaction, reference, metadata = {}) {
    if (!hexTransaction) {
      throw new Error("transaction hex cannot be empty");
    }
    let receiveTxUrl = await this.resolver.getSendTxUrlFor(targetPaymail);
    const response = await this.http.postJson(receiveTxUrl, this.requestBodyFactory.buildBodySendTx(hexTransaction, reference, metadata));
    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Server failed with: ${body}`);
    }
    return response.json();
  }
  async getP2pPaymentDestination(targetPaymail, satoshis) {
    if (!satoshis) {
      throw new Error("Amount in satohis needs to be specified");
    }
    let paymentDestinationUrl = await this.resolver.getP2pPaymentDestinationUrlFor(targetPaymail);
    const response = await this.http.postJson(paymentDestinationUrl, this.requestBodyFactory.buildBodyP2pPaymentDestination(satoshis));
    if (response.status === HttpStatus.NOT_FOUND) {
      throw new PaymailNotFound(`Paymail ${targetPaymail} not found`, targetPaymail);
    }
    if (!response.ok) {
      throw new PaymailServerError(`Paymail server for ${targetPaymail} returned an invalid response`);
    }
    const body = await response.json();
    if (!body.outputs) {
      throw new PaymailServerError("Server answered with a wrong format. Missing outputs");
    }
    return body;
  }
  async getP2pPaymentDestinationWithTokensSupport(targetPaymail, amount, asset, protocol) {
    const UNAVAILABLE_FOR_LEGAL_REASONS = 451;
    if (!amount) {
      throw new Error("Amount needs to be specified");
    }
    let paymentDestinationUrl = await this.resolver.getP2pPaymentDestinationWithTokensSupportUrlFor(targetPaymail);
    const response = await this.http.postJson(paymentDestinationUrl, {
      amount,
      asset,
      protocol
    });
    if (response.status === HttpStatus.NOT_ACCEPTABLE) {
      throw new ProtocolNotSupported(`Protocol ${protocol} is not supported by paymail ${targetPaymail}`, protocol);
    }
    if (response.status === HttpStatus.NOT_FOUND) {
      throw new PaymailNotFound(`Paymail ${targetPaymail} not found`, targetPaymail);
    }
    if (response.status === UNAVAILABLE_FOR_LEGAL_REASONS) {
      throw new AssetNotAccepted(`Paymail ${targetPaymail} cannot accept asset ${asset}`);
    }
    if (!response.ok) {
      throw new PaymailServerError(`Paymail server for ${targetPaymail} returned an invalid response`);
    }
    const body = await response.json();
    if (!body.outputs) {
      throw new PaymailServerError("Server answered with a wrong format. Missing outputs");
    }
    return body;
  }
  async sendSfpBuildAction(targetAssetPaymail, params) {
    const buildActionUrl = await this.resolver.getSfpBuildActionUrlFor(targetAssetPaymail);
    const response = await this.http.postJson(buildActionUrl, params);
    if (!response.ok) {
      const body = await response.json();
      throw new PaymailServerError(body.message);
    }
    return response.json();
  }
  async sendSfpAuthoriseAction(targetAssetPaymail, params) {
    let authoriseActionUrl = await this.resolver.getSfpAuthoriseActionUrlFor(targetAssetPaymail);
    const response = await this.http.postJson(authoriseActionUrl, params);
    if (!response.ok) {
      const body = await response.json();
      throw new Error(body.message);
    }
    return response.json();
  }
  async getAssetInformation(assetTargetPaymail) {
    let assetInformationUrl = await this.resolver.getAssetInformationUrlFor(assetTargetPaymail);
    const response = await this.http.get(assetInformationUrl);
    if (response.status === HttpStatus.NOT_FOUND) {
      throw new Error(`Asset ${assetTargetPaymail} was not found`);
    }
    if (!response.ok) {
      const body = await response.text();
      throw new Error(`Server failed with: ${body}`);
    }
    return response.json();
  }
}

export { AssetNotAccepted, BrowserDns, CapabilityCodes, Clock, EndpointResolver, PaymailClient, PaymailNotFound, PaymailServerError, ProtocolNotSupported, RequestBodyFactory, VerifiableMessage };
//# sourceMappingURL=paymail-client.esm.js.map
