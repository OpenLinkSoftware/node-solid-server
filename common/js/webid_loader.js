
YouID_Loader = function () {
  this.verify_query = `
  PREFIX foaf:<http://xmlns.com/foaf/0.1/> 
  PREFIX schema: <http://schema.org/> 
  PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#> 
  PREFIX owl:  <http://www.w3.org/2002/07/owl#> 
  PREFIX cert: <http://www.w3.org/ns/auth/cert#> 
  PREFIX oplcert: <http://www.openlinksw.com/schemas/cert#> 
  PREFIX acl: <http://www.w3.org/ns/auth/acl#> 
  PREFIX pim: <http://www.w3.org/ns/pim/space#> 
  PREFIX ldp: <http://www.w3.org/ns/ldp#> 
  PREFIX skos: <http://www.w3.org/2004/02/skos/core#> 
  PREFIX as: <http://www.w3.org/ns/activitystreams#> 
  PREFIX vcard: <http://www.w3.org/2006/vcard/ns#>

  SELECT * WHERE 
    { 
       {{?url foaf:primaryTopic ?webid .} UNION 
        {?url schema:mainEntity ?webid .} 
       }
       {{?webid schema:name ?schema_name} UNION 
        {?webid foaf:name ?foaf_name} UNION 
        {?webid rdfs:label ?rdfs_name} UNION 
        {?webid skos:prefLabel ?skos_prefLabel} UNION 
        {?webid skos:altLabel ?skos_altLabel} 
        UNION 
        {?url schema:name ?schema_name} UNION 
        {?url foaf:name ?foaf_name} UNION 
        {?url rdfs:label ?rdfs_name} UNION 
        {?url skos:prefLabel ?skos_prefLabel} UNION 
        {?url skos:altLabel ?skos_altLabel} 
       } 
       OPTIONAL { ?webid oplcert:hasIdentityDelegate ?delegate} 
       OPTIONAL { ?webid oplcert:onBehalfOf ?behalfOf} 
       OPTIONAL { ?webid acl:delegates ?acl_delegates} 
       OPTIONAL { ?webid pim:storage ?pim_store } 
       OPTIONAL { ?webid ldp:inbox ?inbox } 
       OPTIONAL { ?webid as:outbox ?outbox } 
       OPTIONAL { ?webid foaf:knows ?knows } 
       OPTIONAL {
        ?webid cert:key ?pubkey . 
        ?pubkey cert:modulus ?mod .  
        ?pubkey cert:exponent ?exponent . 
        ?pubkey a ?alg . 
       }
       OPTIONAL { ?webid foaf:mbox ?foaf_mbox . }
       OPTIONAL { ?webid vcard:email ?vcard_email . }
       OPTIONAL { ?webid schema:email ?schema_email . }
    }`;

  this.verify_pubkey = `
  PREFIX foaf:<http://xmlns.com/foaf/0.1/> 
  PREFIX schema: <http://schema.org/> 
  PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#> 
  PREFIX owl:  <http://www.w3.org/2002/07/owl#> 
  PREFIX cert: <http://www.w3.org/ns/auth/cert#> 
  PREFIX oplcert: <http://www.openlinksw.com/schemas/cert#> 
  PREFIX acl: <http://www.w3.org/ns/auth/acl#> 
  PREFIX pim: <http://www.w3.org/ns/pim/space#> 
  PREFIX ldp: <http://www.w3.org/ns/ldp#> 
  SELECT * WHERE 
    { 
       {{?url foaf:primaryTopic ?webid .} UNION 
        {?url schema:mainEntity ?webid .} 
       }
       OPTIONAL { ?webid cert:key ?pubkey} 
    }`;
};

YouID_Loader.prototype = {

  verify_ID : async function(uri, oidc_fetch) {
    var self = this;
    var baseURI = new URL(uri);
        baseURI.hash = '';
        baseURI = baseURI.toString();

    var get_url = uri + ((/\?/).test(uri) ? "&" : "?") + (new Date()).getTime();
    var {data, content_type} = await (this.getProfile(get_url, oidc_fetch)
            .catch(err => {
              throw new Error("Could not load data from: "+uri+"\nError: "+err);
            }));

    var store = await (this.load_data(baseURI, data, content_type)
            .catch(err => {
              throw new Error("Could not parse data from: "+uri+"\nError: "+err);
            }));

    var ret;
    var i = 0;

    while(i < 3) {
      ret = await this.exec_query(store, this.verify_query);
      if (!ret.err && (ret.results && ret.results.length==0) && i < 3) {
        i++;
        continue;
      }
      break;
    }

    // process results
    if (ret.err || (ret.results && ret.results.length==0)) {
      if (err) {
        throw new Error("Could not extract profile data\n"+(err?err:""));
      } else {
        var {err, res} = await this.exec_query(store, this.verify_pubkey);

        var verify_pkey = {pubkey:null, url:null, webid:null};
                       
        for(var i=0; i < res.length; i++) {
          if (res[i].url && String(res[i].url.value).lastIndexOf(baseURI, 0)!=0)
            continue;
          if (res[i].pubkey)
            verify_pkey.pubkey = res[i].pubkey.value
          if (res[i].url)
            verify_pkey.url = res[i].url.value
          if (res[i].webid)
            verify_pkey.webid = res[i].webid.value
        }

        if (!verify_pkey.pubkey && verify_pkey.url && verify_pkey.webid) {
          throw new Error("Could not extract profile data.\n"+
                        "The next item is missing from the profile\n"+
                        "document associated with the input WebID:\n"+
                        "?webid cert:key ?pubkey .\n");
        } else {
          throw new Error("Could not extract profile data.\n"+
                        "At least one of the following is missing from the profile\n"+
                        "document associated with the input WebID:\n"+
                        "{webid-profile-doc-url} foaf:primaryTopic ?webid \n"+
                        " OR \n"+
                        "{webid-profile-doc-url} schema:mainEntity ?webid .");
        }
      }
    }

    var results = ret.results;

    var profile = {data, content_type, baseURI};
    var youid = { id: null, name: null, alg: null, pubkey: null, email:null,
          mod: null, exp: null, delegate: null,
          acl: [], behalfOf: [], foaf_knows:[],
          pim: null, inbox: null, outbox: null };

    var url, acl_delegates, behalfOf, foaf_knows;
    var schema_name, foaf_name, rdfs_name, skos_prefLabel, skos_altLabel;

    acl_delegates = {};
    behalfOf = {};
    foaf_knows = {};

    for(var i=0; i < results.length; i++) {
      var r = results[i];
      if (r.url && String(r.url.value).lastIndexOf(baseURI, 0)!=0)
        continue;

      if (r.delegate)
        youid.delegate = r.delegate.value;
      if (r.acl_delegates)
        acl_delegates[r.acl_delegates.value] = 1;
      if (r.behalfOf)
        behalfOf[r.behalfOf.value] = 1;
      if (r.knows)
        foaf_knows[r.knows.value] = 1;
      if (r.pim_store)
        youid.pim = r.pim_store.value;
      if (r.inbox)
        youid.inbox = r.inbox.value;
      if (r.outbox)
        youid.outbox = r.outbox.value;

      if (r.url)
        url = r.url.value;
      if (r.pubkey)
        youid.pubkey = r.pubkey.value;
      if (r.alg)
        youid.alg = r.alg.value;
      if (r.mod)
        youid.mod = r.mod.value;
      if (r.exponent)
        youid.exp = r.exponent.value;
      if (r.webid)
        youid.id = r.webid.value;

      if (r.schema_name)
        schema_name = r.schema_name.value;
      if (r.foaf_name)
        foaf_name = r.foaf_name.value;
      if (r.rdfs_name)
        rdfs_name = r.rdfs_name.value;
      if (r.skos_prefLabel)
        skos_prefLabel = r.skos_prefLabel.value;
      if (r.skos_altLabel)
        skos_altLabel = r.skos_altLabel.value;

        if (r.foaf_mbox) {
          var s = r.foaf_mbox.value;
          if (s.startsWith('mailto:'))
            youid.email = s.substring(7);
          else
            youid.email = s;
        }
        if (r.vcard_email) 
            youid.email = r.vcard_email.value;
        if (r.schema_email) 
            youid.email = r.schema_email.value;

    }
    if (skos_prefLabel)
      youid.name = skos_prefLabel;
    else if (skos_altLabel)
      youid.name = skos_altLabel;
    else if (schema_name)
      youid.name = schema_name
    else if (foaf_name)
      youid.name = foaf_name;
    else if (rdfs_name)
      youid.name = rdfs_name;

    var _tmp = Object.keys(acl_delegates);
    for(var i=0; i<_tmp.length; i++)
      youid.acl.push(_tmp[i]);

    var _tmp = Object.keys(behalfOf);
    for(var i=0; i<_tmp.length; i++)
      youid.behalfOf.push(_tmp[i]);

    var _tmp = Object.keys(foaf_knows);
    for(var i=0; i<_tmp.length; i++)
      youid.foaf_knows.push(_tmp[i]);

    var msg, success;
//    if (youid.id && youid.pubkey && youid.mod && youid.exp && youid.name) {
    if (youid.id && youid.name) {
      msg = 'Successfully verified.';
      success = true;
    } else {
      msg = 'Failed, could not verify WebID.';
      success = false;
    }

    return {success, youid, msg, profile};
  },


  getProfile : function(url, oidc_fetch) {
    var _fetch = oidc_fetch || fetch;
    return new Promise( (resolve, reject) => {
      var options = {
        method: 'GET',
        headers: {
          'Accept': 'text/turtle;q=1.0,application/ld+json;q=0.5,text/plain;q=0.2,text/html;q=0.5,*/*;q=0.1',
//          'Accept': 'text/turtle, application/ld+json'
        }
      }

      _fetch(url, options)
        .then(function(response) {
          if (!response.ok) {
            var err = 'HTTP ' + response.status + ' ' + response.statusText;
	    reject (err)
          }

          var header = response.headers.get('content-type');
          response.text().then((data) => {
              resolve({data, content_type: header});
          });
        })
        .catch(err => { 
          reject(err); 
        }) ;
    })
  }, 


  load_data : function(baseURI, data, content_type) {

    var self = this;
    return new Promise(function(resolve, reject) {

      rdfstore.Store.yieldFrequency(15);
      rdfstore.create(function(err, store) {

        var options = {documentIRI:baseURI};
          
        switch(content_type)
        {
        case 'text/turtle':
        case 'application/ld+json':
          store.load(content_type, data, options, function(err, res){
	    if (err) {
              reject ("Could not parse profile\n\n"+err+"\n\n Profile data:\n\n"+data);
	    }

	    resolve(store);
	  });
	  break;

	default:
          reject ("Unexpected content type :"+content_type);
        }
      })
    })
  },


  exec_query : function(store, query) {
    var self = this;
    return new Promise((resolve, reject) => {
      store.execute(query, function(err, results) {
        resolve({err, results});
      })
    })
  },

  getCertKeys : async function(profile, webid) {
    var self = this;
    var store;

    try {
      store = await this.load_data(profile.baseURI, profile.data, profile.content_type);
    } catch(err) {
      var msg = "Could not parse data from: "+profile.baseURI+"\nError: "+err;
      return { "error": msg};
    }

    var q = `
  PREFIX terms: <http://purl.org/dc/terms/> 
  PREFIX rd: <http://www.w3.org/2000/01/rdf-schema#> 
  PREFIX cert: <http://www.w3.org/ns/auth/cert#> 
  PREFIX foaf: <http://xmlns.com/foaf/0.1/> 
  PREFIX vcard: <http://www.w3.org/2006/vcard/ns#>
  PREFIX schema: <http://schema.org/> 

  SELECT * WHERE 
    { 
      {
       <${webid}> cert:key ?pubkey .
       ?pubkey a cert:RSAPublicKey ;
              cert:modulus  ?cert_mod ;
              cert:exponent ?cert_exp .
      }
       OPTIONAL { ?pubkey terms:created ?key_cr_dt . }
       OPTIONAL { ?pubkey terms:title   ?key_cr_title . }
       OPTIONAL { ?pubkey rd:label ?key_label . }
    }`;

    var rc;
    try {
      rc = await this.exec_query(store, q);
    } catch(err) {
      return { "error": err};
    }
    if (rc.err) {
      return { "error": rc.err};
    } 
    else if (!rc.err && rc.results && rc.results.length > 0) 
    {
      var ret = [];
      for (var i=0; i < rc.results.length; i++) {
        var r = rc.results[i];
        var pkey = r.pubkey.value;
        try {
          pkey = r.pubkey.token==='blank' ? r.pubkey.value : (new URL(r.pubkey.value)).hash;
        } catch(e) {
        }

        var v = {pkey, mod:r.cert_mod.value, exp:r.cert_exp.value};
        if (r.key_cr_dt) 
          v["key_created"] = r.key_cr_dt.value;
        if (r.key_cr_title) 
          v["key_title"] = r.key_cr_title.value;
        if (r.key_label) 
          v["key_label"] = r.key_label.value;

        ret.push(v);
      }
      return {keys: ret};
   }
   else {
      return { "error": 'No data'};
   }
  } ,

}



SPARQL = function () {
  this.store = null;
}
SPARQL.prototype = {
  load_data : function(baseURI, data, content_type) {

    var self = this;
    return new Promise(function(resolve, reject) {

      rdfstore.Store.yieldFrequency(15);
      rdfstore.create(function(err, store) {

        self.store = store;
        var options = {documentIRI:baseURI};
          
        switch(content_type)
        {
        case 'text/turtle':
        case 'application/ld+json':
          store.load(content_type, data, options, function(err, res){
	    if (err) {
              reject ("Could not parse profile\n\n"+err+"\n\n Profile data:\n\n"+data);
	    }

	    resolve(true);
	  });
	  break;

	default:
          reject ("Unexpected content type :"+content_type);
        }
      })
    })
  },


  exec_query : function(query) {
    var self = this;
    return new Promise((resolve, reject) => {
      self.store.execute(query, function(err, results) {
        resolve({err, results});
      })
    })
  },
}

