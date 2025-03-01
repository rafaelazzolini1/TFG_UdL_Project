import React from 'react';
import { Link } from 'react-router-dom';

export default function ForgotPasswordLink() {
  return (
    <div className="text-sm">
      <Link to="/password-recovery" className="font-medium text-blue-400 hover:text-blue-300">
        Esqueceu sua senha?
      </Link>
    </div>
  );
}
