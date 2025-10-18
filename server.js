const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

// Configuración de sesiones
app.use(session({
    secret: process.env.SESSION_SECRET || 'studysecret',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

const DATA_PATH = path.join(__dirname, 'data.json');

// Middleware para proteger rutas
function requireAuth(req, res, next) {
    if (req.session.user) {
        next();
    } else {
        res.status(401).json({ error: 'No autorizado' });
    }
}

// Funciones para manejar datos
function readData() {
    try {
        if (!fs.existsSync(DATA_PATH)) {
            const initialData = { users: [], habits: [] };
            writeData(initialData);
            return initialData;
        }
        const data = fs.readFileSync(DATA_PATH, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error leyendo datos:', error);
        return { users: [], habits: [] };
    }
}

function writeData(data) {
    try {
        fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2));
    } catch (error) {
        console.error('Error escribiendo datos:', error);
    }
}

// Validaciones
function validateUsername(username) {
    if (!username || typeof username !== 'string') return 'Usuario requerido';
    if (username.length < 3) return 'El usuario debe tener al menos 3 caracteres';
    if (username.length > 20) return 'El usuario no puede tener más de 20 caracteres';
    if (!/^[a-zA-Z0-9_]+$/.test(username)) return 'El usuario solo puede contener letras, números y guión bajo';
    return null;
}

function validatePassword(password) {
    if (!password || typeof password !== 'string') return 'Contraseña requerida';
    if (password.length < 6) return 'La contraseña debe tener al menos 6 caracteres';
    if (password.length > 100) return 'La contraseña es demasiado larga';
    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
        return 'La contraseña debe contener al menos una mayúscula, una minúscula y un número';
    }
    return null;
}

function validateHabit(materia, horas, fecha) {
    const errors = {};
    
    if (!materia || typeof materia !== 'string' || materia.trim() === '') {
        errors.materia = 'La materia es requerida';
    } else if (materia.length > 50) {
        errors.materia = 'La materia no puede tener más de 50 caracteres';
    }
    
    const horasNum = parseFloat(horas);
    if (!horas || isNaN(horasNum) || horasNum <= 0) {
        errors.horas = 'Las horas deben ser un número positivo';
    } else if (horasNum > 24) {
        errors.horas = 'No puedes estudiar más de 24 horas al día';
    }
    
    if (!fecha) {
        errors.fecha = 'La fecha es requerida';
    } else {
        const fechaObj = new Date(fecha);
        const hoy = new Date();
        if (fechaObj > hoy) {
            errors.fecha = 'La fecha no puede ser futura';
        }
    }
    
    return Object.keys(errors).length > 0 ? errors : null;
}

// Rutas de API

// Registro de usuario
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const usernameError = validateUsername(username);
        if (usernameError) {
            return res.status(400).json({ error: usernameError });
        }
        
        const passwordError = validatePassword(password);
        if (passwordError) {
            return res.status(400).json({ error: passwordError });
        }
        
        const data = readData();
        
        if (data.users.find(u => u.username === username)) {
            return res.status(400).json({ error: 'El usuario ya existe' });
        }
        
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        data.users.push({ 
            username, 
            password: hashedPassword,
            createdAt: new Date().toISOString()
        });
        writeData(data);
        
        res.json({ message: 'Usuario registrado exitosamente' });
    } catch (error) {
        console.error('Error en registro:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
        }
        
        const data = readData();
        const user = data.users.find(u => u.username === username);
        
        if (!user) {
            return res.status(400).json({ error: 'Usuario o contraseña incorrecta' });
        }
        
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(400).json({ error: 'Usuario o contraseña incorrecta' });
        }
        
        req.session.user = username;
        res.json({ message: 'Login exitoso', user: username });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error cerrando sesión:', err);
            return res.status(500).json({ error: 'Error cerrando sesión' });
        }
        res.clearCookie('connect.sid');
        res.json({ message: 'Sesión cerrada exitosamente' });
    });
});

// Agregar hábito
app.post('/api/habits', requireAuth, (req, res) => {
    try {
        const { materia, horas, fecha } = req.body;
        
        const validationErrors = validateHabit(materia, horas, fecha);
        if (validationErrors) {
            return res.status(400).json({ errors: validationErrors });
        }
        
        const data = readData();
        
        const newHabit = {
            id: Date.now().toString(),
            user: req.session.user,
            materia: materia.trim(),
            horas: parseFloat(horas),
            fecha,
            createdAt: new Date().toISOString()
        };
        
        data.habits.push(newHabit);
        writeData(data);
        
        res.json({ message: 'Hábito agregado exitosamente', habit: newHabit });
    } catch (error) {
        console.error('Error agregando hábito:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Obtener hábitos del usuario
app.get('/api/habits', requireAuth, (req, res) => {
    try {
        const data = readData();
        const userHabits = data.habits
            .filter(h => h.user === req.session.user)
            .sort((a, b) => new Date(b.fecha) - new Date(a.fecha));
        
        res.json({ habits: userHabits });
    } catch (error) {
        console.error('Error obteniendo hábitos:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Eliminar hábito
app.delete('/api/habits/:id', requireAuth, (req, res) => {
    try {
        const habitId = req.params.id;
        const data = readData();
        
        const habitIndex = data.habits.findIndex(h => 
            h.id === habitId && h.user === req.session.user
        );
        
        if (habitIndex === -1) {
            return res.status(404).json({ error: 'Hábito no encontrado' });
        }
        
        data.habits.splice(habitIndex, 1);
        writeData(data);
        
        res.json({ message: 'Hábito eliminado exitosamente' });
    } catch (error) {
        console.error('Error eliminando hábito:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Obtener estadísticas del usuario
app.get('/api/stats', requireAuth, (req, res) => {
    try {
        const data = readData();
        const userHabits = data.habits.filter(h => h.user === req.session.user);
        
        const totalHours = userHabits.reduce((sum, h) => sum + h.horas, 0);
        const totalSessions = userHabits.length;
        const avgHours = totalSessions > 0 ? (totalHours / totalSessions) : 0;
        
        const subjectStats = {};
        userHabits.forEach(habit => {
            if (!subjectStats[habit.materia]) {
                subjectStats[habit.materia] = { hours: 0, sessions: 0 };
            }
            subjectStats[habit.materia].hours += habit.horas;
            subjectStats[habit.materia].sessions += 1;
        });
        
        const now = new Date();
        const fourWeeksAgo = new Date(now.getTime() - 28 * 24 * 60 * 60 * 1000);
        const recentHabits = userHabits.filter(h => new Date(h.fecha) >= fourWeeksAgo);
        
        const weeklyStats = {};
        recentHabits.forEach(habit => {
            const week = getWeekNumber(new Date(habit.fecha));
            if (!weeklyStats[week]) {
                weeklyStats[week] = 0;
            }
            weeklyStats[week] += habit.horas;
        });
        
        res.json({
            totalHours: Math.round(totalHours * 10) / 10,
            totalSessions,
            avgHours: Math.round(avgHours * 10) / 10,
            subjectStats,
            weeklyStats
        });
    } catch (error) {
        console.error('Error obteniendo estadísticas:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Verificar sesión
app.get('/api/session', (req, res) => {
    if (req.session.user) {
        res.json({ authenticated: true, user: req.session.user });
    } else {
        res.json({ authenticated: false });
    }
});

function getWeekNumber(date) {
    const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
    const dayNum = d.getUTCDay() || 7;
    d.setUTCDate(d.getUTCDate() + 4 - dayNum);
    const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
    return Math.ceil((((d - yearStart) / 86400000) + 1) / 7);
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use('*', (req, res) => {
    res.status(404).json({ error: 'Ruta no encontrada' });
});

app.use((error, req, res, next) => {
    console.error('Error no manejado:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
});

app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
    console.log(`📊 StudyTracker listo para usar`);
});

module.exports = app;