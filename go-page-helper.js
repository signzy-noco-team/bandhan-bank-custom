const AES_MODES = {
  alpha: CryptoJS.mode.CBC,
  beta: CryptoJS.mode.CFB,
  gamma: CryptoJS.mode.OFB,
  delta: CryptoJS.mode.CTR,
  epsilon: 'GCM', // Special handling for GCM
};
const PADDING_SCHEMES = {
  alpha: CryptoJS.pad.Pkcs7,
  beta: CryptoJS.pad.NoPadding,
  gamma: CryptoJS.pad.Iso10126,
  delta: CryptoJS.pad.AnsiX923,
  epsilon: CryptoJS.pad.Iso97971,
  zeta: CryptoJS.pad.ZeroPadding,
};
const AES_KEY_SIZES = {
  tau: 128,
  phi: 192,
  psi: 256,
};
const RSA_PADDING_SCHEMES = {
  omega: 'OAEP',
  theta: 'PSS',
  lambda: 'PKCS1-v1_5',
};
const HASH_ALGORITHMS = {
  sigma: 'SHA-256',
  tau: 'SHA-1',
  phi: 'SHA-512',
  psi: 'MD5',
};

function getEncryptionConfig(eVersion) {
  if (!eVersion) {
    return null;
  }
  const [aesModeKey, aesPaddingKey, aesKeySizeKey, rsaPaddingKey, oaepHashKey] =
    eVersion.split('.');
  const aesKeySize = AES_KEY_SIZES[aesKeySizeKey];
  const aesMode = AES_MODES[aesModeKey];
  const aesPadding = PADDING_SCHEMES[aesPaddingKey];
  const rsaPadding = rsaPaddingKey ? RSA_PADDING_SCHEMES[rsaPaddingKey] : undefined;
  const oaepHash = oaepHashKey ? HASH_ALGORITHMS[oaepHashKey] : undefined;
  if (!aesKeySize || !aesMode || !aesPadding || (rsaPaddingKey && !rsaPadding)) {
    throw new Error(`Unsupported configuration: ${eVersion}`);
  }
  return {
    aesKeySize,
    aesMode,
    aesPadding,
    rsaPadding,
    oaepHash,
  };
}

function generateAESKey(config) {
  const aesKey = forge.random.getBytesSync(config.aesKeySize / 8);
  return aesKey;
}

function generateEncryptedAESKey(aesKey, publicKeyPem, cryptoConfig) {
  try {
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    let encryptedString;
    if (cryptoConfig.rsaPadding === 'OAEP') {
      encryptedString = publicKey.encrypt(aesKey, 'RSA-OAEP', {
        md:
          cryptoConfig.oaepHash && forge.md[cryptoConfig.oaepHash]
            ? forge.md[cryptoConfig.oaepHash].create()
            : forge.md.sha256.create(),
      });
    } else if (cryptoConfig.rsaPadding === 'PKCS1-v1_5') {
      encryptedString = publicKey.encrypt(aesKey, 'RSAES-PKCS1-V1_5');
    } else if (cryptoConfig.rsaPadding === 'PSS') {
      encryptedString = publicKey.encrypt(aesKey, 'RSA-PSS', {
        mgf: cryptoConfig.mgf1Hash
          ? forge.mgf.mgf1.create(forge.md[cryptoConfig.mgf1Hash])
          : forge.md.sha256.create(),
        saltLength: 20,
      });
    } else {
      throw new Error('Unsupported RSA Padding scheme');
    }
    const encodedEncryptedKey = forge.util.encode64(encryptedString);
    return encodedEncryptedKey;
  } catch (error) {
    throw error;
  }
}

function encryptPayload(config, aesKey, payload) {
  if (config.aesMode === 'GCM') {
    const iv = forge.random.getBytesSync(12);
    const cipher = forge.cipher.createCipher('AES-GCM', aesKey);
    cipher.start({iv});
    cipher.update(forge.util.createBuffer(payload, 'utf8'));
    cipher.finish();
    return {
      encryptedString: forge.util.encode64(cipher.output.getBytes()),
      iv: forge.util.encode64(iv),
      authTag: forge.util.encode64(cipher.mode.tag.getBytes()),
    };
  } else {
    const iv = CryptoJS.lib.WordArray.random(16);
    const encrypted = CryptoJS.AES.encrypt(payload, CryptoJS.enc.Hex.parse(aesKey), {
      iv: CryptoJS.enc.Hex.parse(iv.toString(CryptoJS.enc.Hex)),
      mode: config.aesMode,
      padding: config.aesPadding,
    });
    return {encryptedString: encrypted.toString(), iv: iv.toString(CryptoJS.enc.Hex)};
  }
}

function decryptPayload(config, aesKey, encryptedData, iv, authTag) {
  if (config.aesMode === 'GCM') {
    const decipher = forge.cipher.createDecipher('AES-GCM', aesKey);
    decipher.start({
      iv: forge.util.decode64(iv),
      tag: forge.util.decode64(authTag),
    });
    decipher.update(forge.util.createBuffer(forge.util.decode64(encryptedData)));
    const success = decipher.finish();
    if (!success) {
      throw new Error('Decryption failed. Invalid tag or corrupted data.');
    }
    return decipher.output.toString('utf8');
  } else {
    const decrypted = CryptoJS.AES.decrypt(encryptedData, CryptoJS.enc.Hex.parse(aesKey), {
      iv: CryptoJS.enc.Hex.parse(iv),
      mode: config.aesMode,
      padding: config.aesPadding,
    });
    return decrypted.toString(CryptoJS.enc.Utf8);
  }
}

function sha256Encrypt(data) {
  if (data) return CryptoJS.SHA256(data).toString(CryptoJS.enc.Hex);
  return '';
}

// The e-version is in the format "aesMode.aesPadding.aesKeySize.rsaPadding.oaepHash"
const eVersion = 'epsilon.alpha.tau.omega.sigma';
const config = getEncryptionConfig(eVersion);
const aesKey = generateAESKey(config);
const base64PublicKey = `LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KICAgICAgICBNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXVPcjhLNy82T1hrbUlNdlBkTnI2CiAgICAgICAgNGRGaDRDQkc0QjRyTEpHOWJHNFMxYlFqbWdHZHFqQ1grNUtWL1VoZVVUZ3VWem9yTDJGRTVnRkMyV1ljeWVnZAogICAgICAgIHB0Q3R0eXhHdmpRY25lelhvK29WZUp5WWl3MUVtWjRVbGZtY0M4VkxPNGdEd2dscTVWSERTbWJUQ1dpZk1KVUMKICAgICAgICBhQU81cXpFUXJ3REx0V3Nlak40Qi85N3hFSCtMbE0ybk9oQWlHaUxCYkdjMURtVDhwRTB6aituditnRXBwVUhuCiAgICAgICAgZDJVUkp1NUM0YUNjRzM0bDY1TUtqcDRlV0V0elV1RjdIWXQyaUI0UDM1N05EWk91NGVJOVVPMEExc21XQUFRTQogICAgICAgIEZjWnNoNTJ6dzdmZ2lGaWJXUFdFM0h1c09lWXBvNUJraEQ4cGo0OWhpUVU1emVXUjMwaHNIam9ZR3d1dUxkZSsKICAgICAgICBpUUlEQVFBQgogICAgICAgIC0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ==`;

function convertBase64ToPem(base64Key) {
  const rawKey = atob(base64Key);
  return `-----BEGIN PUBLIC KEY-----\n${rawKey.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
}

const publicKeyPem = convertBase64ToPem(base64PublicKey);

function makeAjaxRequest(url, query, method, dataType, data, callback, options = {}) {
  if (!url) {
    return false;
  }
  const baseHeaders = {
    'x-trace-id': sessionStorage.getItem('traceId') || '',
    'X-Product-Code': sessionStorage.getItem('X-Product-Code') ?? 'N/A',
  };
  let reqObj = {url, method, dataType, data, headers: baseHeaders, success: null, error: null};
  if (options?.reqOptions && Object.keys(options.reqOptions)?.length > 0) {
    Object.assign(reqObj, options.reqOptions);
  }
  if (config && method?.toUpperCase() === 'POST') {
    reqObj.dataType = 'text';
    const encryptedAESKey = generateEncryptedAESKey(aesKey, publicKeyPem, config);
    let encryptedPayload;
    let iv;
    let authTag;
    if (config.aesMode === 'GCM') {
      const {
        iv: GCMiv,
        authTag: GCMauthTag,
        encryptedString,
      } = encryptPayload(config, aesKey, JSON.stringify(data));
      iv = GCMiv;
      authTag = GCMauthTag;
      encryptedPayload = encryptedString;
    } else {
      const {encryptedString, iv: payloadIv} = encryptPayload(
        config,
        aesKey,
        JSON.stringify(data),
      );
      iv = payloadIv;
      encryptedPayload = encryptedString;
    }
    if (options?.isDirectAjax) {
      reqObj.data = JSON.stringify({
        ev: eVersion,
        pa: encryptedPayload,
        xe: encryptedAESKey,
        xs: iv,
        xtd: baseHeaders['x-trace-id'],
        xpc: baseHeaders['X-Product-Code'],
        ...(authTag && {xl: authTag}),
      });
      reqObj.headers = {
        'Content-Type': 'application/json',
      };
    } else {
      reqObj.data = encryptedPayload;
      reqObj.headers = {
        ...baseHeaders,
        'Content-Type': 'text/plain',
        'e-version': eVersion,
        'x-encrypted': encryptedAESKey,
        'x-iv': iv,
        ...(authTag && {'x-tag': authTag}),
      };
    }
  }
  reqObj.success = function (res) {
    try {
      if (config) {
        const [responseIv, encryptedPayload, responseTag] = res.split('::');
        let decryptedData;
        if (config.aesMode === 'GCM') {
          decryptedData = decryptPayload(
            config,
            aesKey,
            encryptedPayload,
            responseIv,
            responseTag,
          );
        } else {
          decryptedData = decryptPayload(config, aesKey, encryptedPayload, responseIv);
        }
        callback(JSON.parse(decryptedData));
      } else {
        callback(JSON.parse(res.responseText));
      }
    } catch (e) {
      console.error('Error while processing AJAX response.', e);
      callback(res);
    }
  };
  reqObj.error = function (err) {
    console.error('AJAX request failed.', {
      status: err.status,
      statusText: err.statusText,
      response: err.responseText,
    });
    callback(err);
  };
  $.ajax(reqObj);
}

function GoPageHelper() {
  return {
    prefillPageData: function () {
      try {
        var pageData = sessionStorage.getItem('currentPage');
        var customUIPageData = null;
        if (pageData) {
          pageData = JSON.parse(pageData);
          if (pageData.uiConfig?.[0]?.customUIPageData && Object.keys(pageData.uiConfig[0].customUIPageData).length > 0) {
            customUIPageData = pageData.uiConfig[0].customUIPageData;
          }
        }

        function findValueByKeyName(keyName) {
          return customUIPageData?.[keyName] || null;
        }

        $('input[type="text"],input[type="email"],input[type="number"]').each(function () {
          var name = $(this).attr('name');
          if (!name) {
            name = $(this).attr('goid');
          }
          if (name) {
            name = name.trim();
            var value = findValueByKeyName(name);
            if (value) {
              $(this).val(value);
            }
          }
        });
        $('select').each(function () {
          var name = $(this).attr('name') || $(this).attr('goid') || '';
          name = name.trim();
          if (name) {
            var value = findValueByKeyName(name);
            if (value) {
              $(this).val(value).trigger('change');
            }
          }
        });
        $('.btn_group').each(function () {
          var name = $(this).children().first().attr('name');
          if (name) {
            name = name.trim();
            var value = findValueByKeyName(name);
            if (value) {
              $(this)
                .find('[name="' + name + '"]')
                .removeClass('active');
              $(this)
                .find('[name="' + name + '"]')
                .each(function () {
                  if ($(this).text() === value) {
                    $(this).addClass('active').trigger('click');
                  }
                });
            }
          }
        });
        $('input[type="radio"]').each(function () {
          var name = $(this).attr('name');
          if (!name) {
            name = $(this).attr('goid');
          }
          if (name) {
            name = name.trim();
            var value = findValueByKeyName(name);
            if (value === $(this).val()) {
              $(this).trigger('click');
            }
          }
        });
      } catch (e) {
        console.log(e);
      }
    },
    ajaxRequest: function (options) {
      const { url, query, method, type, dataType, data, success, async, delay, cache } =
      options || {}; // Destructure only the required fields
      const ajaxOptions = {
        isDirectAjax: true,
      };
      const reqOptions = {};
      if (delay) reqOptions.delay = delay;
      if (cache) reqOptions.cache = cache;
      ajaxOptions.reqOptions = reqOptions;
      return makeAjaxRequest(url, query, method || type, dataType, data, success, ajaxOptions);
    },
    initModernDropDown: function ({
                                           appDomain,
                                           tableName,
                                           fieldId,
                                           fieldName,
                                           placeholder = 'Select',
                                           columns,
                                           column_value_elementIds = [],
                                           labelField,
                                           valueField,
                                           fullResult = true,
                                           page = 1,
                                           limit = 10,
                                           uniqueConstraint = true,
                                           additionalValuesToStore = {},
                                           formName,
                                           filterIds = [],
                                           orderBy = '',
                                           orderDirection = 'asc',
                                           startsWith = false,
                                         }) {
      $(fieldId).select2({
        placeholder: placeholder,
        minimumInputLength: 0,
        ajax: {
          transport: (params, success, failure) => {
            const searchConfig = this.prepareSearchConfig(
              appDomain,
              tableName,
              columns,
              column_value_elementIds,
              fullResult,
              false,
              limit,
              page,
              params.data?.term || '',
              startsWith,
            );
            searchConfig.data = { ...searchConfig.data, term: params.data?.term || '' };
            this.ajaxRequest({
              ...searchConfig,
              success: function (data) {
                success(data);
              },
              error: function (error) {
                console.error('AJAX request failed:', error);
                failure(error);
              },
            });
          },
          processResults: function (data, params) {
            if (typeof data === 'string') {
              data = JSON.parse(data);
            }
            if (!data || !Array.isArray(data.data)) {
              console.error('Invalid response format:', data);
              return { results: [] };
            }
            let filteredResult = data.data || [];
            // Apply ID filtering
            if (Array.isArray(filterIds) && filterIds.length > 0) {
              filteredResult = filteredResult.filter((item) =>
                filterIds.includes(item[valueField]),
              );
            }
            // Apply sorting only if orderBy exists and is a valid key
            if (orderBy && filteredResult.length > 0 && orderBy in filteredResult[0]) {
              const sortOrder = orderDirection.toLowerCase() === 'desc' ? -1 : 1;
              filteredResult.sort((a, b) => (a[orderBy] > b[orderBy] ? sortOrder : -sortOrder));
            }
            if (params.term) {
              const searchTerm = params.term.toLowerCase();
              filteredResult = filteredResult.filter((item) =>
                item[labelField]?.toLowerCase().includes(searchTerm),
              );
              filteredResult.sort((a, b) => {
                const aLabel = a[labelField]?.toLowerCase() || '';
                const bLabel = b[labelField]?.toLowerCase() || '';
                const aStarts = aLabel.startsWith(searchTerm) ? 0 : 1;
                const bStarts = bLabel.startsWith(searchTerm) ? 0 : 1;
                if (aStarts !== bStarts) return aStarts - bStarts;
                return aLabel.localeCompare(bLabel);
              });
            }
            return {
              results: filteredResult.map((item) => ({
                id: item[valueField],
                text: item[labelField],
                allData: item,
              })),
            };
          },
          cache: true,
        },
      });
      // On Change - update hidden inputs when a value is selected
      $(fieldId).on('select2:select', function (e) {
        const selectedData = e.params.data.allData;
        const form = $(`#${formName}`);
        for (let [apiKey, hiddenInputName] of Object.entries(additionalValuesToStore)) {
          if (selectedData[apiKey] !== undefined) {
            form.find(`[goid="${hiddenInputName}"]`).remove();
            form.append(
              `<input type="hidden" gotype='input' goid="${hiddenInputName}" value="${selectedData[apiKey]}">`,
            );
          }
        }
      });
      const pageData = JSON.parse(sessionStorage.getItem('currentPage') || '{}');
      const customUIPageData = pageData?.uiConfig?.[0]?.customUIPageData || {};
      // Initial API call without query string
      this.ajaxRequest({
        ...this.prepareSearchConfig(
          appDomain,
          tableName,
          columns,
          column_value_elementIds,
          fullResult,
          false,
          limit,
          page,
          '',
          startsWith,
        ),
        success: function (queryResponse) {
          if (typeof queryResponse === 'string') {
            queryResponse = JSON.parse(queryResponse);
          }
          let filteredResult = queryResponse.data || [];
          // Apply ID filtering
          if (Array.isArray(filterIds) && filterIds.length > 0) {
            filteredResult = filteredResult.filter((item) => filterIds.includes(item[valueField]));
          }
          // Apply sorting only if orderBy exists and is a valid key
          if (orderBy && filteredResult.length > 0 && orderBy in filteredResult[0]) {
            const sortOrder = orderDirection.toLowerCase() === 'desc' ? -1 : 1;
            filteredResult.sort((a, b) => (a[orderBy] > b[orderBy] ? sortOrder : -sortOrder));
          }
          // if (fullResult === false) {
          const options = filteredResult.map(
            (item) => new Option(item[labelField], item[valueField], false, false),
          );
          $(fieldId).append(options).trigger('change');
          // }
          // Set the value, creating a new option if necessary
          if ($(fieldId).find(`option[value="${customUIPageData?.[fieldName]}"]`).length) {
            $(fieldId).val(customUIPageData?.[fieldName]).trigger('change');
          } else {
            // If labelField and valueField are the same, use the field value as both text and id
            let optionText = customUIPageData?.[`${fieldName} label`];
            // When labelField and valueField are the same, use the field value itself as the display text
            if (labelField === valueField && customUIPageData?.[fieldName]) {
              optionText = customUIPageData?.[fieldName];
            }
            const newOption = new Option(optionText, customUIPageData?.[fieldName], true, true);
            // Add as the first option in the dropdown
            $(fieldId).prepend(newOption).trigger('change');
          }
          // Find and store selected data in hidden fields
          let selectedData = filteredResult.find(
            (item) => item[valueField] === customUIPageData?.[fieldName],
          );
          // If selected data is not found in the filtered results and labelField and valueField are the same,
          // create a custom selectedData object with the value as both id and text
          if (!selectedData && labelField === valueField && customUIPageData?.[fieldName]) {
            selectedData = {
              [valueField]: customUIPageData?.[fieldName],
              [labelField]: customUIPageData?.[fieldName],
            };
          }
          if (selectedData) {
            const form = $(`#${formName}`);
            for (let [apiKey, hiddenInputName] of Object.entries(additionalValuesToStore)) {
              if (selectedData[apiKey] !== undefined) {
                form.find(`[goid="${hiddenInputName}"]`).remove();
                form.append(
                  `<input type="hidden" gotype='input' goid="${hiddenInputName}" value="${selectedData[apiKey]}">`,
                );
              }
            }
          }
        },
      });
    },
  }
}