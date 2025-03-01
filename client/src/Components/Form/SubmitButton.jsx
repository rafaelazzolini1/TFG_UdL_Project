// src/components/Form/SubmitButton.jsx
import React from 'react';

const SubmitButton = ({ label }) => (
  <button
    type="submit"
    className="w-full py-2 px-4 bg-blue-500 text-white rounded-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50 transition duration-200"
  >
    {label}
  </button>
);

export default SubmitButton;
