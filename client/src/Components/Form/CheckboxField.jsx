// src/components/Form/CheckboxField.jsx
import React from 'react';

const CheckboxField = ({ id, label, register, errors }) => (
  <div className="flex items-center space-x-2">
    <input
      type="checkbox"
      id={id}
      className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
      {...register(id, { required: true })}
    />
    <label htmlFor={id} className="text-sm text-gray-300">
      {label}
    </label>
    {errors && (
      <p className="text-red-500 text-xs italic transition-opacity duration-500">{errors.message}</p>
    )}
  </div>
);

export default CheckboxField;
