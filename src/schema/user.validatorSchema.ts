import Joi from "joi";

export const createUserSchema = Joi.object({
  firstName: Joi.string().required(),
  lastName: Joi.string().required(),
  email: Joi.string().email().required(),
  password: Joi.string().required(),
  passwordConfirm: Joi.string()
  .valid(Joi.ref('password'))
  .required()
  .messages({
    'any.only': 'Password confirmation does not match password',
  }),
  country: Joi.string().required(),
  city: Joi.string().required(),
  address: Joi.string().required(),
  phoneNumber: Joi.string().required(),
  referralCode: Joi.string().optional(),
});

export const loginUserSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});
