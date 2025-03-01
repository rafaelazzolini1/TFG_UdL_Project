// src/components/Form/InputField.jsx
import React from 'react';

const InputField = ({
  id,
  label,
  type,
  register,
  errors,
  focusedField,
  handleFocus,
  handleBlur,
  isFilled,
  validationRules
}) => (
  <div className="relative">
    <label
      htmlFor={id}
      className={`absolute left-3 transition-all duration-300 ${focusedField === id || isFilled(id) ? '-top-2 text-xs text-blue-400 bg-gray-800 px-1' : 'top-2 text-sm text-gray-400'}`}
    >
      {label}
    </label>
    <input
      id={id}
      type={type}
      className={`w-full px-3 py-2 bg-gray-700 border rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors duration-200 ${errors ? 'border-red-500' : 'border-gray-600'}`}
      {...register(id, validationRules)}
      onFocus={() => handleFocus(id)}
      onBlur={handleBlur}
    />
    {errors && (
      <p className="text-red-500 text-xs italic transition-opacity duration-500">{errors.message}</p>
    )}
  </div>
);

export default InputField;
