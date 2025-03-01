import React, { useState, useEffect } from 'react';
import {
  UsersIcon,
  LogOutIcon,
  MoreVerticalIcon,
  CheckIcon,
  ChartLineIcon,
  ArrowRightFromLineIcon,
  SearchIcon,
  ArrowDown01Icon,
  ArrowUp10Icon
} from 'lucide-react';

import { useNavigate, useLocation } from 'react-router-dom';
import { collection, getDocs, updateDoc, doc } from 'firebase/firestore';
import { auth, db } from './Services/FirebaseConfig.js';
import { signOut } from 'firebase/auth';
import sodium from 'libsodium-wrappers';


const MenuItem = ({ icon: Icon, text, isActive, onClick }) => (
  <li
    className={`flex items-center space-x-2 px-4 py-2 rounded-lg cursor-pointer ${
      isActive ? 'bg-blue-600 text-white' : 'text-gray-300 hover:bg-gray-700'
    }`}
    onClick={onClick}
  >
    <Icon className="h-5 w-5" />
    <span>{text}</span>
  </li>
);

export default function AdminDashboard() {
  const [activeItem, setActiveItem] = useState('Usuários');
  const [users, setUsers] = useState([]);
  const [filteredUsers, setFilteredUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isInitialLoad, setIsInitialLoad] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const [editingUser, setEditingUser] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [searchPosition, setSearchPosition] = useState('');
  const [initialFilter, setInitialFilter] = useState('Todos');

  const navigate = useNavigate();

  const menuItems = [
    { icon: UsersIcon, text: 'Usuários' },
    // { icon: ChartLineIcon, text: 'Dashboard' },
    { icon: ArrowRightFromLineIcon, text: 'Acessar Chat' },
  ];

  const positionOptions = ['Todos', 'Funcionário', 'Gestor', 'Main-admin'];

  useEffect(() => {
    const fetchUsers = async () => {
      if (!isInitialLoad) setLoading(true);
      try {
        const usersCollection = collection(db, 'Users');
        const userSnapshot = await getDocs(usersCollection);
        const userList = userSnapshot.docs.map(doc => ({
          id: doc.id,
          ...doc.data(),
          position: doc.data().position || 'user'
        }));
        const sortedUsers = userList.sort((a, b) => a.name.localeCompare(b.name));
        setUsers(sortedUsers);
        const filteredList = initialFilter === 'Todos' 
          ? sortedUsers 
          : sortedUsers.filter(user => user.position === initialFilter);
        setFilteredUsers(filteredList);
        setSearchPosition(initialFilter);
      } catch (error) {
        console.error("Error fetching users:", error);
      } finally {
        setLoading(false);
        setIsInitialLoad(false);
      }
    };

    fetchUsers();
  }, [isInitialLoad, initialFilter]);

  useEffect(() => {
    const filtered = users.filter(user => 
      (user.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
       user.email.toLowerCase().includes(searchTerm.toLowerCase())) &&
      (searchPosition === 'Todos' || user.position === searchPosition)
    );
    setFilteredUsers(filtered);
    setCurrentPage(1);
  }, [searchTerm, searchPosition, users]);

  const updateUserPosition = async (userId, newPosition) => {
    let messageToEncrypt;
    if (newPosition === "Main-admin") {
      messageToEncrypt = "Main-admin";
    } else if (newPosition === "Gestor") {
      messageToEncrypt = "Gestor";
    } else if (newPosition === "Funcionário") {
      messageToEncrypt = "funcionario";
    } else {
      console.error("Posição inválida");
      return;
    }

    const keyBase64 = 'q9egeDk+L1t2C8pgH/9rzE/ezPflr3cx6JLujZSiaX8=';
    const key = sodium.from_base64(keyBase64, sodium.base64_variants.ORIGINAL);
    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);

    const encryptedMessage = sodium.crypto_secretbox_easy(sodium.from_string(messageToEncrypt), nonce, key);
    const fullMessage = new Uint8Array([...nonce, ...encryptedMessage]);
    const encryptedMessageBase64 = sodium.to_base64(fullMessage, sodium.base64_variants.ORIGINAL);

    try {
      const userRef = doc(db, 'Users', userId);
      await updateDoc(userRef, { position: newPosition, tokenKey: encryptedMessageBase64 });

      setUsers(users.map(user =>
        user.id === userId ? { ...user, position: newPosition, tokenKey: encryptedMessageBase64 } : user
      ));

    } catch (error) {
      console.error("Erro ao atualizar a posição do usuário:", error);
    }
  };

  const handleLogout = async () => {
    try {
      await signOut(auth);
      sessionStorage.removeItem('authToken');
      sessionStorage.removeItem('userRole');
      navigate('/login');
    } catch (error) {
      console.error("Erro ao fazer logout:", error);
    }
  };

  const location = useLocation();
  const email = location.state?.email;
  const [userEmail, setUserEmail] = useState('');
  const [token, setToken] = useState("");

  useEffect(() => {
    const emailFromState = location.state?.email;
    const tokenCryptFromState = location.state?.tokenCrypt;
    
    const params = new URLSearchParams(location.search);
    const emailFromParams = params.get('email');
  
    setUserEmail(emailFromState || emailFromParams || '');
    setToken(tokenCryptFromState || '');

    console.log("Token recebido:", token);
  }, [location]);

  const handleChangeChat = async () => {
    try {
      navigate('/front-chat', { state: { email: userEmail, tokenCrypt: token } });
    } catch (error) {
      console.error("Erro ao acessar o chat:", error);
    }
  };

  const renderContent = () => {
    switch (activeItem) {
      case 'Usuários':
        return (
          <div className="bg-gray-800 rounded-lg p-6">
            <div className="mb-4 flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-4">
              <div className="relative">
                <input
                  type="text"
                  name="searchTerm"
                  id="searchTerm"
                  className="w-full sm:w-64 px-4 py-2 bg-[#f0f0f0] text-[#2c3e50] rounded-md pl-10"
                  placeholder="Buscar nome ou email"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
                <SearchIcon className="absolute left-3 top-2.5 h-5 w-5 text-[#6a9fad]" />
              </div>
              <select
                id="searchPosition"
                name="searchPosition"
                className="w-full sm:w-auto px-4 py-2 bg-[#f0f0f0] text-[#2c3e50] rounded-md"
                value={searchPosition}
                onChange={(e) => {
                  setSearchPosition(e.target.value);
                  setInitialFilter(e.target.value);
                }}
              >
                {positionOptions.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </div>
            {loading ? (
              <p className="text-white">Carregando usuários...</p>
            ) : (
              <>
                <table className="min-w-full divide-y divide-gray-700">
                  <thead>
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Nome</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Email</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">Posição</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider"></th>
                    </tr>
                  </thead>
                  <tbody className="bg-gray-800 divide-y divide-gray-700">
                    {filteredUsers.slice((currentPage - 1) * 10, currentPage * 10).map((user) => (
                      <tr key={user.id}>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">{user.name}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">{user.email}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                          <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                            user.position === 'Main-admin' ? 'bg-purple-100 text-purple-800' :
                            user.position === 'Gestor' ? 'bg-blue-100 text-blue-800' :
                            'bg-green-100 text-green-800'
                          }`}>
                            {user.position}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <div className="relative">
                            <button
                              onClick={() => setEditingUser(editingUser === user.id ? null : user.id)}
                              className="text-gray-300 hover:text-white"
                            >
                              <MoreVerticalIcon className="h-5 w-5" />
                            </button>
                            {editingUser === user.id && (
                              <div className="absolute right-0 z-10 mt-2 w-48 rounded-md shadow-lg bg-gray-700 ring-1 ring-black ring-opacity-5">
                                <div className="py-1" role="menu" aria-orientation="vertical" aria-labelledby="options-menu">
                                  {['Funcionário', 'Gestor', 'Main-admin'].map((position) => (
                                    <button
                                      key={position}
                                      onClick={() => updateUserPosition(user.id, position)}
                                      className="block w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-gray-600 hover:text-white"
                                      role="menuitem"
                                    >
                                      {position}
                                      {user.position === position && (
                                        <CheckIcon className="h-4 w-4 inline-block ml-2" />
                                      )}
                                    </button>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div className="mt-4 flex justify-between">
                  <button
                    onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                    disabled={currentPage === 1}
                    className="px-4 py-2 bg-blue-600 text-white rounded disabled:opacity-50"
                  >
                    Anterior
                  </button>
                  <button
                    onClick={() => setCurrentPage(prev => prev + 1)}
                    disabled={currentPage * 10 >= filteredUsers.length}
                    className="px-4 py-2 bg-blue-600 text-white rounded disabled:opacity-50"
                  >
                    Próxima
                  </button>
                </div>
              </>
            )}
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className="flex h-screen bg-gray-900 text-[#f0f0f0]">
      <aside className="hidden md:flex flex-col w-64 bg-gray-800">
        <div className="p-4">
          <h1 className="text-2xl font-bold">Painel de Administração</h1>
        </div>
        <nav className="flex-1">
          <ul className="space-y-2 py-4">
            {menuItems.map((item) => (
              <MenuItem
                key={item.text}
                icon={item.icon}
                text={item.text}
                isActive={activeItem === item.text}
                onClick={() => {
                  setActiveItem(item.text);
                  if (item.text === 'Acessar Chat') handleChangeChat();
                }}
              />
            ))}
          </ul>
        </nav>
        <div className="p-6 mt-auto pt-8 border-gray-700">
          <button onClick={handleLogout} className="flex items-center space-x-2 text-red-500 hover:text-red-600 ">
            <LogOutIcon className="h-5 w-5" />
            <span>Logout</span>
          </button>
        </div>
      </aside>
      <main className="flex-1 p-8 overflow-auto">
        <h2 className="text-3xl font-semibold mb-4">{activeItem}</h2>
        {isInitialLoad ? (
          <p className="text-white">Carregando dados iniciais...</p>
        ) : activeItem === 'Usuários' ? (
          renderContent()
        ) : null}
      </main>
    </div>
  );
}