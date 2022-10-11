const Joi  = require('@hapi/joi');
const Hoek = require('hoek');

// Internals
const internals = {};

/**
 * Assert that the params are valid for the type passed in
 *
 * @param type    - The type of object we want to validate for. i.e. route, plugin
 * @param options  - The JSON object to be validated
 * @param message  - Part of the message if validation fails
 * @returns {*}
 */
exports.assert = function (type, options, message) {

  const validationObj = Joi.validate(options, internals[type]);
  let error           = validationObj.error;
  let errorMessage    = null;

  // If there is an error, build a nice error message
  if (error) {
    errorMessage = error.name + ':';
    error.details.forEach(function (err) {
      errorMessage += ' ' + err.message;
    });
  } else {
    const { permissions } = validationObj.value
    if (permissions && !Array.isArray(permissions)) {
      const childrenAreObjects = (obj) => {
        for (let k in obj) {
          if (typeof obj[k] !== 'object') {
            return k;
          } else {
            const ret = childrenAreObjects(obj[k]);
            if (ret) {
              return ret;
            }
          }
        }

        return false;
      }

      const ret = childrenAreObjects(permissions);
      if (ret) {
        error = true;
        errorMessage = new Error(`${ret} in permissions hierarchy object should be an object`);
      }
    }

  }

  // If there is an error build the error message
  Hoek.assert(!error, 'Invalid', type, 'options', message ? '(' + message + ')' : '', errorMessage);

  return validationObj.value;
};


/**
 * Validation rules for a route's params
 */
internals.route = Joi.object({
  permission       : Joi.string().optional(),
  permissions      : Joi.array().optional(),
  aclQuery         : Joi.func().when('validateEntityAcl', { is: true, then: Joi.required() }),
  aclQueryParam    : Joi.string().default('id'),
  paramSource      : Joi.string().allow('payload', 'params', 'query').default('params'),
  validateEntityAcl: Joi.boolean().default(false),
  validateAclMethod: Joi.string().default(null),
  entityUserField  : Joi.string().default("_user"),
  entityPermissionField  : Joi.string().default("permission"),
  userIdField      : Joi.string().default("_id"),
  userPermissionField    : Joi.string().default("permission")
}).without('permission', 'permissions').options({ allowUnknown: false });


/**
 * Validation rules for the plugin's params
 */
internals.plugin = Joi.object({
  permissions  : Joi.alternatives().try(Joi.array().optional(), Joi.object().optional()).optional(),
  userPath     : Joi.string().default('auth.credentials')
}).options({ allowUnknown: false });
