import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App';
import './app.css';

const el = document.getElementById('root');
if (!el) throw new Error('#root 를 찾지 못했습니다');
createRoot(el).render(<StrictMode><App/></StrictMode>);
