import React from 'react';
import { Link } from 'react-router-dom';

export default function SignUpLink() {
  return (
    <div className="mt-6 border-t border-gray-700 pt-6">
      <p className="text-center text-sm text-gray-400">
        Não tem uma conta?{' '}
        <Link to="/signup" className="text-blue-400 hover:text-blue-300 transition-colors duration-200">
          Cadastrar
        </Link>
      </p>
    </div>
  );
}
