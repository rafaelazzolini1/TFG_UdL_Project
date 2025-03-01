// InputField.jsx
import React from 'react';
import { AlertCircle } from 'lucide-react';

export default function InputField({ id, type, label, value, onChange, error, onFocus, onBlur, focused }) {
  return (
    <div className="y-2 relative">
      <label htmlFor={id} className={`absolute left-3 transition-all ${focused || value ? '-top-3 text-xs text-blue-400 bg-gray-800 px-1' : 'top-2 text-sm text-gray-400'}`}>
        {label}
      </label>
      <input
        id={id}
        name={id}
        type={type}
        value={value}
        onChange={onChange}
        onFocus={onFocus}
        onBlur={onBlur}
        className={`w-full px-3 py-2 bg-gray-700 border ${error ? 'border-red-500' : 'border-gray-600'} rounded-md text-white focus:outline-none`}
      />
      {error && (
        <p className="text-red-500 text-xs italic flex items-center mt-1">
          <AlertCircle className="h-4 w-4 mr-1" />
          {error}
        </p>
      )}
    </div>
  );
}
