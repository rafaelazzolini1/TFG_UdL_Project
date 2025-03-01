// src/components/Form/SuccessMessage.jsx
import React from 'react';

const SuccessMessage = ({ message }) => (
  <div className="mb-4 p-4 bg-green-500 text-white rounded-md">
    {message}
  </div>
);

export default SuccessMessage;
