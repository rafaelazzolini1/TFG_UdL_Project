import React from 'react';

const LockIcon = ({ className = 'h-6 w-6', color = 'currentColor' }) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      viewBox="0 0 24 24"
      fill={color}
    >
      <path
        fillRule="evenodd"
        d="M12 2a4 4 0 00-4 4v4H7a1 1 0 00-1 1v10a1 1 0 001 1h10a1 1 0 001-1V11a1 1 0 00-1-1h-1V6a4 4 0 00-4-4zm2 8V6a2 2 0 10-4 0v4h4z"
        clipRule="evenodd"
      />
    </svg>
  );
}

export default LockIcon;
