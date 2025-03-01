// src/components/Form/FormMessage.jsx
import React from 'react';

const FormMessage = ({ message }) => (
  <p className="text-red-500 text-xs italic transition-opacity duration-500">{message}</p>
);

export default FormMessage;
