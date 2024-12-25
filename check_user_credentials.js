const Joi = require("joi");

const checkUserRegistration = Joi.object({
  id: Joi.string().uuid().required().messages({
    "string.guid": "User ID must be in a valid UUIDv4 format!",
    "any.required": "User ID is required!",
  }),
  user_name: Joi.string()
    .max(50)
    .pattern(/^[a-zA-Z]+(?: [a-zA-Z]+)*$/)
    .required()
    .messages({
      "string.pattern.base":
        "User name must only contain letters, with optional single spaces between words!",
      "string.max": "User name must be 50 characters or less!",
      "any.required": "User name is required!",
    }),
  email: Joi.string().email().required().messages({
    "string.email": "Invalid email address format!",
    "any.required": "Email address is required!",
  }),
  password: Joi.string()
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&*!]).{8,}$/)
    .required()
    .messages({
      "string.pattern.base":
        "Password must include at least one uppercase letter, one lowercase letter, one digit, one special character (@#$%^&*!), and be at least 8 characters long!",
      "any.required": "Password is required!",
    }),
});

const checkLoginUserData = Joi.object({
  email: Joi.string().email().required().messages({
    "string.email": "Invalid email address format!",
    "any.required": "Email address is required!",
  }),
  password: Joi.string()
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&*!]).{8,}$/)
    .required()
    .messages({
      "string.pattern.base":
        "Password must include at least one uppercase letter, one lowercase letter, one digit, one special character (@#$%^&*!), and be at least 8 characters long!",
      "any.required": "Password is required!",
    }),
});

const checkUserTask = Joi.object({
  status: Joi.string()
    .valid("Pending", "In Progress", "Completed")
    .required()
    .messages({
      "any.only": "Status should be either Pending, In Progress, or Completed",
      "any.required": "Status is required!",
    }),
  priority: Joi.string().valid("Low", "Medium", "High").required().messages({
    "any.only": "Priority should be either Low, Medium, or High",
    "any.required": "Priority is required!",
  }),
  date: Joi.date().required().messages({
    "date.base": "date must be a valid date!",
    "any.required": "Event date is required!",
  }),
});

const checkStatus = Joi.object({
  status: Joi.string()
    .valid("Pending", "In Progress", "Completed")
    .required()
    .messages({
      "any.only": "Status should be either Pending, In Progress, or Completed",
      "any.required": "Status is required!",
    }),
});

module.exports = {
  checkUserRegistration,
  checkLoginUserData,
  checkUserTask,
  checkStatus,
};
