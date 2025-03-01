// PasswordField.jsx
import React from 'react';
import { Eye, EyeOff, AlertCircle } from 'lucide-react';

export default function PasswordField({ id, label, value, onChange, error, showPassword, toggleShowPassword, onFocus, onBlur, focused }) {
  return (
    <div className="y-2 relative">
      <label htmlFor={id} className={`absolute left-3 transition-all ${focused || value ? '-top-3 text-xs text-blue-400 bg-gray-800 px-1' : 'top-2 text-sm text-gray-400'}`}>
        {label}
      </label>
      <input
        id={id}
        name={id}
        type={showPassword ? 'text' : 'password'}
        value={value}
        onChange={onChange}
        onFocus={onFocus}
        onBlur={onBlur}
        className={`w-full px-3 py-2 bg-gray-700 border ${error ? 'border-red-500' : 'border-gray-600'} rounded-md text-white pr-10 focus:outline-none`}
      />
      <button type="button" className="absolute inset-y-0 right-0 pr-3 flex items-center" onClick={toggleShowPassword}>
        {showPassword ? <EyeOff className="h-5 w-5 text-gray-400" /> : <Eye className="h-5 w-5 text-gray-400" />}
      </button>
      {error && (
        <p className="text-red-500 text-xs italic flex items-center mt-1">
          <AlertCircle className="h-4 w-4 mr-1" />
          {error}
        </p>
      )}
    </div>
  );
}
