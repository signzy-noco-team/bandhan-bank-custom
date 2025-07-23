// Form validator for Bandhan Bank Account Opening Process
/**
 * Get all field validation types
 * @returns {Array} List of validation types
 */
function getAllFieldsToValidate() {
  return [
    'isValidMobileNumber',
    'isValidIndianMobileNumber',
    'isNumber',
    'isLengthOk',
    'isValidEmail',
    'numberInRange',
    'isValidResetPassword',
    'isEqualTo',
    'isCardNo',
    'validateList',
    'isPAN',
    'isIndividualPAN',
    'isAadhaar',
    'isIndividualAadhaar',
    'isPinCode',
    'isIndianPinCode',
    'isIndianIFSCCode',
  ];
}

/**
 * Create validator instance
 * @returns {Object} Validator object with validation methods
 */
function validator() {
  return {
    validateForm: function (formId, customValidations = []) {
      formId = '#' + formId;
      var _this = this;
      var status = true;
      $(formId + ' .required').each(function () {
        var element = $(this);
        var elementVal = $(this).val();
        var errorMsgId = element.attr('data-errormsg');
        var validateList = element.attr('data-groupname');
        var isElementsNeedValidation = false;
        if (!elementVal && !validateList) {
          _this.markError(formId, element, errorMsgId);
          status = false;
          return;
        }
        $.each(getAllFieldsToValidate(), function (index, value) {
          if (element.hasClass(value)) {
            isElementsNeedValidation = true;
            var errorStatus = _this.validateFieldType(formId, value, element, elementVal, errorMsgId);
            if (!errorStatus && status) {
              status = _this.validateFieldType(formId, value, element, elementVal, errorMsgId);
            }
          }
        });
        if (!isElementsNeedValidation) {
          _this.unMarkError(formId, element, errorMsgId);
        }
      });
      let customValidationStatus = true;
      if (customValidations && Array.isArray(customValidations)) {
        customValidations.forEach((validationFn) => {
          customValidationStatus = customValidationStatus && validationFn();
        })
      }
      return status && customValidationStatus;
    },
    singleFieldValidation: function (formId, element) {
      var _this = this;
      formId = '#' + formId;
      var status = true;
      var elementVal = element.val();
      var errorMsgId = element.attr('data-errormsg');
      var validateList = element.attr('data-groupname');
      var isElementsNeedValidation = false;
      if (!elementVal && !validateList) {
        this.markError(formId, element, errorMsgId);
        status = false;
        return;
      }
      $.each(getAllFieldsToValidate(), function (index, value) {
        if (element.hasClass(value)) {
          isElementsNeedValidation = true;
          var errorStatus = _this.validateFieldType(formId, value, element, elementVal, errorMsgId);
          if (!errorStatus && status) {
            status = _this.validateFieldType(formId, value, element, elementVal, errorMsgId);
          }
        }
      });
      if (!isElementsNeedValidation) {
        this.unMarkError(formId, element, errorMsgId);
      }
      return status;
    },
    validateFieldType: function (formId, fieldType, element, elementVal, errorMsgId) {
      if (typeof this[fieldType] === 'function') {
        return this[fieldType](elementVal, element) ?
          this.unMarkError(formId, element, errorMsgId) :
          this.markError(formId, element, errorMsgId);
      }
      return false;
    },
    isNumber: function (input) {
      return !isNaN(input);
    },
    numberInRange: function (input, element) {
      const sanitizedInput = input.replace(/,/g, '');
      const inputInt = Number(sanitizedInput);
      const min = $(element).data('min');
      const max = $(element).data('max');
      if (!this.isNumber(sanitizedInput)) {
        return false;
      }
      return inputInt >= min && inputInt <= max;
    },
    isLengthOk: function (input, element) {
      const trimmedInput = input.trim();
      const minLength = element.data('minlength');
      const maxLength = element.prop('maxlength');
      return trimmedInput.length >= minLength && trimmedInput.length <= maxLength;
    },
    isValidEmail: function (email) {
      var emailRegex = /^[-0-9a-zA-Z.+_]+@[-0-9a-zA-Z.+_]+\.[a-zA-Z]{2,4}$/;
      return emailRegex.test(email);
    },
    isPAN: function (pan) {
      const pattern = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/;
      return pattern.test(pan);
    },
    isIndividualPAN: function (pan) {
      const pattern = /^[A-Z]{3}P[A-Z](?!0000)[0-9]{4}[A-Z]{1}$/;
      return pattern.test(pan);
    },
    isAadhaar: function (input) {
      const normalAadhaarPattern = /^[0-9]{12}$/;
      const virtualAadhaarPattern = /^[0-9]{16}$/;
      if (input.length > 16) {
        return false;
      }
      return normalAadhaarPattern.test(input) || virtualAadhaarPattern.test(input);
    },
    isIndividualAadhaar: function (input) {
      input = input.replace(/[^0-9]/g, '');
      const normalAadhaarPattern = /^[2-9][0-9]{11}$/;
      const virtualAadhaarPattern = /^[2-9][0-9]{15}$/;
      if (input.length !== 12 && input.length !== 16) {
        return false;
      }
      return normalAadhaarPattern.test(input) || virtualAadhaarPattern.test(input);
    },
    isPinCode: function (input) {
      const pincodePattern = /^[0-9]{6}$/;
      if (input.length !== 6) {
        return false;
      }
      return pincodePattern.test(input);
    },
    isIndianPinCode: function (input) {
      const pattern = /^[1-9][0-9]{5}$/;
      return pattern.test(input);
    },
    isValidUserName: function (userName) {
      userName = userName.trim();
      return userName.length >= 4;
    },
    isValidAmount: function (amount) {
      var amountRegex = /^[1-9]\d+$/;
      return amountRegex.test(amount);
    },
    isValidMobileNumber: function (mobileNumber) {
      var mobileNumberTrimmed = mobileNumber.trim();
      var requiredLength = 10;
      var specialCharRegex = /^[\w{./\\(),'}:?®©-]+$/;
      var isValidNumber = mobileNumberTrimmed > 0;
      var hasSpecialChars = specialCharRegex.test(mobileNumberTrimmed);
      var isSatisfyLength = mobileNumberTrimmed.length === requiredLength;
      return (isValidNumber && hasSpecialChars && isSatisfyLength);
    },
    isValidIndianMobileNumber: function (mobileNumber) {
      var mobileNumberTrimmed = mobileNumber.trim();
      var pattern = /^[6-9][0-9]{9}$/;
      return pattern.test(mobileNumberTrimmed);
    },
    isEqualTo: function (password, element) {
      var equalField = element.data('equalto');
      return $(equalField).val() === password;
    },
    isIndianIFSCCode: function (ifsc) {
      const ifscPattern = /^[A-Z]{4}0[A-Z0-9]{6}$/;
      return ifscPattern.test(ifsc);
    },
    isCardNo: function (input, element) {
      var inputEdited = input.replace(/ /g, '');
      var minLength = element.data('minlength');
      var maxLength = element.prop('maxlength');
      return inputEdited.length >= minLength && inputEdited.length <= maxLength;
    },
    validateList: function (input, element) {
      var groupName = element.data('groupname');
      var status = false;
      $('[name="' + groupName + '"]').each(function () {
        if ($(this).is(':checked')) {
          status = true;
        }
      });
      return status;
    },
    markError: function (formId, element, errorMsgId) {
      var className = '.' + errorMsgId;
      $(formId).find(className).show();
      element.addClass('error-field');
      var formField = element.closest('.form-field');
      if (element.hasClass('js_select2_input')) {
        var selectField = element.parent().find('.select2-container--default');
        $(selectField).addClass('error-field');
      }
      if (element.hasClass('select2')) {
        element.parent().addClass('error-field');
      }
      formField.removeClass('verified-field').addClass('error-info');
      return false;
    },
    unMarkError: function (formId, element, errorMsgId) {
      var className = '.' + errorMsgId;
      $(formId).find(className).hide();
      element.removeClass('error-field');
      const formField = element.closest('.form-field');
      formField.removeClass('error-info').addClass('verified-field');
      if (element.hasClass('js_select2_input')) {
        var selectField = element.parent().find('.select2-container--default');
        selectField.removeClass('error-field');
      }
      if (element.hasClass('select2')) {
        element.parent().removeClass('error-field');
      }
      return true;
    },
    isValidTimePeriod: function (years, months, dob) {
      if (!years || !months) {
        return false;
      }
      if (!dob) {
        console.error('DOB received is invalid', dob, new Date(dob));
      }
      const date = moment(dob, 'DD/MM/YYYY');
      const today = moment();
      const stayInMonths = (parseInt(years) * 12) + parseInt(months);
      let monthDiff = today.diff(date, 'months');
      if (stayInMonths <= 0 || monthDiff < stayInMonths) {
        return false;
      }
      return true;
    }
  }
};
