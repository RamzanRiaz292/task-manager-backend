const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const moment = require('moment');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'task-manager-secret-key-2024';

// Set timezone to Asia/Karachi (Pakistan Time)
process.env.TZ = 'Asia/Karachi';

app.use(cors());
app.use(express.json());

// Hardcoded Manager Credentials
const HARDCODED_MANAGER = {
    email: 'Faizan@XtroEdge.com',
    password: 'XtroEdge(manager)0311',
    name: 'Faizan Hamza',
    role: 'manager'
};

// Neon PostgreSQL configuration
const dbConfig = {
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
};

const pool = new Pool(dbConfig);

// Timezone utility functions (using native JavaScript)
const timezoneUtils = {
    // Pakistan time offset in minutes (UTC+5)
    PAKISTAN_OFFSET: 5 * 60 * 60 * 1000, // 5 hours in milliseconds

    // Convert UTC to Pakistan time
    utcToLocal: (utcDate) => {
        if (!utcDate) return null;
        const date = new Date(utcDate);
        return new Date(date.getTime() + timezoneUtils.PAKISTAN_OFFSET);
    },

    // Convert Pakistan time to UTC for database storage
    localToUTC: (localDate) => {
        if (!localDate) return null;
        const date = new Date(localDate);
        return new Date(date.getTime() - timezoneUtils.PAKISTAN_OFFSET);
    },

    // Format date for display
    formatForDisplay: (date) => {
        if (!date) return null;
        return moment(date).format('YYYY-MM-DD HH:mm:ss');
    },

    // Format date for date input (without timezone conversion)
    formatForDateInput: (date) => {
        if (!date) return null;
        return moment(date).format('YYYY-MM-DD');
    },

    // Format datetime for datetime input
    formatForDateTimeInput: (date) => {
        if (!date) return null;
        return moment(date).format('YYYY-MM-DDTHH:mm');
    },

    // Get current time in Pakistan
    getCurrentTime: () => {
        const now = new Date();
        const pakistanTime = new Date(now.getTime() + timezoneUtils.PAKISTAN_OFFSET);
        return moment(pakistanTime).format('YYYY-MM-DD HH:mm:ss');
    },

    // Check if date is today
    isToday: (date) => {
        if (!date) return false;
        const today = new Date();
        const checkDate = new Date(date);
        return today.toDateString() === checkDate.toDateString();
    },

    // Get Pakistan time from any date
    toPakistanTime: (date) => {
        if (!date) return null;
        const utcDate = new Date(date);
        return new Date(utcDate.getTime() + timezoneUtils.PAKISTAN_OFFSET);
    }
};

// Test database connection
const testConnection = async () => {
    try {
        const client = await pool.connect();
        console.log('✅ Connected to Neon PostgreSQL database');
        console.log('⏰ Server Timezone:', process.env.TZ);
        console.log('🕒 Current Pakistan Time:', timezoneUtils.getCurrentTime());
        client.release();
        await initializeDatabase();
    } catch (err) {
        console.error('❌ Database connection failed:', err.message);
        console.log('🔄 Retrying connection in 5 seconds...');
        setTimeout(testConnection, 5000);
    }
};

// Function to initialize database and tables
const initializeDatabase = async () => {
    console.log('🔄 Initializing database...');

    try {
        // Create tables
        await createTables();
        console.log('🎉 Database initialization completed!');
    } catch (err) {
        console.error('❌ Database initialization failed:', err);
    }
};

// Function to create all tables
const createTables = async () => {
    const tables = [
        `CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role VARCHAR(20) DEFAULT 'employee',
            created_by INTEGER DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,

        `CREATE TABLE IF NOT EXISTS tasks (
            id SERIAL PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            assigned_to INTEGER,
            assigned_by INTEGER,
            priority VARCHAR(20) DEFAULT 'medium',
            status VARCHAR(20) DEFAULT 'pending',
            due_date TIMESTAMP NOT NULL,
            estimated_hours INTEGER DEFAULT 1,
            time_spent INTEGER DEFAULT 0,
            progress_percent INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP NULL
        )`,

        `CREATE TABLE IF NOT EXISTS task_progress (
            id SERIAL PRIMARY KEY,
            task_id INTEGER,
            user_id INTEGER,
            progress_percent INTEGER DEFAULT 0,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,

        `CREATE TABLE IF NOT EXISTS holidays (
            id SERIAL PRIMARY KEY,
            date DATE NOT NULL,
            title VARCHAR(255) NOT NULL,
            description TEXT,
            type VARCHAR(20) DEFAULT 'holiday',
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(date)
        )`
    ];

    try {
        for (let i = 0; i < tables.length; i++) {
            await pool.query(tables[i]);
            console.log(`✅ Table ${i + 1} created/verified`);
        }
        await insertHardcodedManager();
    } catch (err) {
        console.error('❌ Table creation failed:', err);
    }
};

// Function to insert hardcoded manager
const insertHardcodedManager = async () => {
    console.log('📥 Setting up hardcoded manager...');

    try {
        const hashedPassword = await bcrypt.hash(HARDCODED_MANAGER.password, 10);

        const managerQuery = `
            INSERT INTO users (name, email, password, role, created_by) 
            VALUES ($1, $2, $3, $4, NULL)
            ON CONFLICT (email) DO UPDATE SET 
            name = EXCLUDED.name, 
            password = EXCLUDED.password, 
            role = EXCLUDED.role
            RETURNING id
        `;

        const result = await pool.query(managerQuery, [
            HARDCODED_MANAGER.name,
            HARDCODED_MANAGER.email,
            hashedPassword,
            HARDCODED_MANAGER.role
        ]);

        const managerId = result.rows[0]?.id || 1;
        console.log('✅ Hardcoded manager setup completed!');
        console.log('📋 Login Credentials:');
        console.log(`   👨‍💼 Manager Email: ${HARDCODED_MANAGER.email}`);
        console.log(`   🔑 Manager Password: ${HARDCODED_MANAGER.password}`);

        await insertSampleEmployees(managerId);
    } catch (err) {
        console.error('❌ Manager setup failed:', err);
    }
};

// Function to insert sample employees
const insertSampleEmployees = async (managerId) => {
    console.log('📥 Creating sample employees...');

    const sampleEmployees = [
        // {
        //     name: 'John Doe',
        //     email: 'john.doe@company.com',
        //     password: 'employee123',
        //     role: 'employee'
        // },
        // {
        //     name: 'Jane Smith',
        //     email: 'jane.smith@company.com',
        //     password: 'employee123',
        //     role: 'employee'
        // }
    ];

    try {
        for (const employee of sampleEmployees) {
            const hashedPassword = await bcrypt.hash(employee.password, 10);
            
            const employeeQuery = `
                INSERT INTO users (name, email, password, role, created_by) 
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (email) DO NOTHING
            `;

            await pool.query(employeeQuery, [
                employee.name,
                employee.email,
                hashedPassword,
                employee.role,
                managerId
            ]);
            
            console.log(`✅ Sample employee: ${employee.email} / ${employee.password}`);
        }

        console.log('🎊 Database setup completed!');
        console.log('\n📋 ALL LOGIN CREDENTIALS:');
        console.log('========================');
        console.log(`👨‍💼 MANAGER: ${HARDCODED_MANAGER.email} / ${HARDCODED_MANAGER.password}`);
        console.log('========================\n');

        // Insert sample holidays and tasks
        await insertSampleHolidays(managerId);
        await insertSampleTasks(managerId);
    } catch (err) {
        console.error('❌ Employee creation failed:', err);
    }
};

// Function to insert sample holidays
const insertSampleHolidays = async (managerId) => {
    console.log('📅 Creating sample holidays...');

    const currentYear = new Date().getFullYear();
    const sampleHolidays = [
        // {
        //     date: `${currentYear}-01-01`,
        //     title: 'New Year Day',
        //     description: 'Public holiday for New Year celebration',
        //     type: 'holiday'
        // },
        // {
        //     date: `${currentYear}-12-25`,
        //     title: 'Christmas Day',
        //     description: 'Christmas holiday',
        //     type: 'holiday'
        // }
    ];

    try {
        for (const holiday of sampleHolidays) {
            const holidayQuery = `
                INSERT INTO holidays (date, title, description, type, created_by) 
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (date) DO NOTHING
            `;

            await pool.query(holidayQuery, [
                holiday.date,
                holiday.title,
                holiday.description,
                holiday.type,
                managerId
            ]);
            
            console.log(`✅ Sample holiday: ${holiday.title} - ${holiday.date}`);
        }
    } catch (err) {
        console.error('❌ Holiday creation failed:', err);
    }
};

// Function to insert sample tasks
const insertSampleTasks = async (managerId) => {
    console.log('📋 Creating sample tasks...');

    const sampleTasks = [
        // {
        //     title: 'Website Redesign',
        //     description: 'Redesign company website with modern UI',
        //     assigned_to: 2, // John Doe
        //     priority: 'high',
        //     due_date: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        //     estimated_hours: 40
        // }
    ];

    try {
        for (const task of sampleTasks) {
            const taskQuery = `
                INSERT INTO tasks (title, description, assigned_to, assigned_by, priority, due_date, estimated_hours) 
                VALUES ($1, $2, $3, $4, $5, $6, $7)
            `;

            await pool.query(taskQuery, [
                task.title,
                task.description,
                task.assigned_to,
                managerId,
                task.priority,
                task.due_date,
                task.estimated_hours
            ]);
            
            console.log(`✅ Sample task: ${task.title} assigned to employee ${task.assigned_to}`);
        }
    } catch (err) {
        console.error('❌ Task creation failed:', err);
    }
};

// Initialize database connection
testConnection();

// ==================== API ROUTES ====================

// Test route with time info
app.get('/api/test', (req, res) => {
    res.json({
        message: '✅ Server is working!',
        database: 'Neon PostgreSQL',
        server_timezone: process.env.TZ,
        current_pakistan_time: timezoneUtils.getCurrentTime(),
        timestamp: new Date().toISOString()
    });
});

// Health check
app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({
            status: 'ok',
            database: 'connected',
            server_timezone: process.env.TZ,
            current_pakistan_time: timezoneUtils.getCurrentTime(),
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        res.status(500).json({
            status: 'error',
            database: 'disconnected',
            error: err.message
        });
    }
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// ==================== AUTH ROUTES ====================

// Login route
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    // First check if it's the hardcoded manager
    if (email === HARDCODED_MANAGER.email) {
        const validPassword = (password === HARDCODED_MANAGER.password);

        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            {
                userId: 1,
                email: HARDCODED_MANAGER.email,
                role: HARDCODED_MANAGER.role,
                name: HARDCODED_MANAGER.name
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        return res.json({
            token,
            user: {
                id: 1,
                name: HARDCODED_MANAGER.name,
                email: HARDCODED_MANAGER.email,
                role: HARDCODED_MANAGER.role
            }
        });
    }

    // Check database for other users
    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1',
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            {
                userId: user.id,
                email: user.email,
                role: user.role,
                name: user.name
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// Create employee (Only manager can do this)
app.post('/api/employees', authenticateToken, async (req, res) => {
    if (req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Access denied. Only managers can create employees.' });
    }

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Name, email and password are required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await pool.query(
            'INSERT INTO users (name, email, password, role, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, role, created_at',
            [name, email, hashedPassword, 'employee', req.user.userId]
        );

        res.json({
            message: 'Employee created successfully',
            employee: result.rows[0]
        });
    } catch (err) {
        if (err.code === '23505') { // Unique violation
            return res.status(400).json({ error: 'Email already exists' });
        }
        console.error('Employee creation error:', err);
        res.status(500).json({ error: 'Failed to create employee' });
    }
});

// Get all employees (for manager)
app.get('/api/employees', authenticateToken, async (req, res) => {
    if (req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Access denied' });
    }

    try {
        const result = await pool.query(
            'SELECT id, name, email, role, created_at FROM users WHERE role = $1 ORDER BY created_at DESC',
            ['employee']
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Employees fetch error:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// ==================== TASK ROUTES ====================

// Get tasks (with proper filtering and timezone conversion)
app.get('/api/tasks', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const userRole = req.user.role;

    let query = `
        SELECT t.*, 
               u1.name as assigned_to_name,
               u2.name as assigned_by_name,
               u1.email as assigned_to_email
        FROM tasks t
        LEFT JOIN users u1 ON t.assigned_to = u1.id
        LEFT JOIN users u2 ON t.assigned_by = u2.id
    `;

    const params = [];

    if (userRole === 'employee') {
        query += ' WHERE t.assigned_to = $1';
        params.push(userId);
    }

    query += ' ORDER BY t.due_date ASC';

    try {
        const result = await pool.query(query, params);
        
        // Convert UTC times to Pakistan time and calculate time remaining
        const tasksWithTime = result.rows.map(task => {
            const pakistanDueDate = timezoneUtils.utcToLocal(task.due_date);
            const pakistanCreatedAt = timezoneUtils.utcToLocal(task.created_at);
            const pakistanCompletedAt = timezoneUtils.utcToLocal(task.completed_at);
            
            const now = new Date();
            const dueDate = new Date(pakistanDueDate);
            const timeRemaining = dueDate.getTime() - now.getTime();

            return {
                ...task,
                due_date: timezoneUtils.formatForDateTimeInput(pakistanDueDate),
                created_at: timezoneUtils.formatForDisplay(pakistanCreatedAt),
                completed_at: timezoneUtils.formatForDisplay(pakistanCompletedAt),
                time_remaining: Math.max(0, timeRemaining),
                is_overdue: timeRemaining < 0 && task.status !== 'completed',
                local_due_date: pakistanDueDate,
                local_created_at: pakistanCreatedAt,
                local_completed_at: pakistanCompletedAt
            };
        });

        res.json(tasksWithTime);
    } catch (err) {
        console.error('Tasks fetch error:', err);
        res.status(500).json({ error: 'Failed to fetch tasks' });
    }
});

// Create task (manager only) with timezone handling
app.post('/api/tasks', authenticateToken, async (req, res) => {
    if (req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Only managers can create tasks' });
    }

    const { title, description, assigned_to, priority, due_date, estimated_hours } = req.body;
    const assigned_by = req.user.userId;

    if (!title || !assigned_to || !due_date) {
        return res.status(400).json({ error: 'Title, assigned_to and due_date are required' });
    }

    try {
        // Convert Pakistan time to UTC for database storage
        const utcDueDate = timezoneUtils.localToUTC(due_date);

        const result = await pool.query(
            `INSERT INTO tasks (title, description, assigned_to, assigned_by, priority, due_date, estimated_hours) 
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
            [title, description, assigned_to, assigned_by, priority, utcDueDate, estimated_hours]
        );

        // Get the created task with user names and convert back to Pakistan time
        const taskResult = await pool.query(
            `SELECT t.*, 
                    u1.name as assigned_to_name,
                    u2.name as assigned_by_name
             FROM tasks t
             LEFT JOIN users u1 ON t.assigned_to = u1.id
             LEFT JOIN users u2 ON t.assigned_by = u2.id
             WHERE t.id = $1`,
            [result.rows[0].id]
        );

        const task = taskResult.rows[0];
        const pakistanTask = {
            ...task,
            due_date: timezoneUtils.formatForDateTimeInput(timezoneUtils.utcToLocal(task.due_date)),
            created_at: timezoneUtils.formatForDisplay(timezoneUtils.utcToLocal(task.created_at)),
            local_due_date: timezoneUtils.utcToLocal(task.due_date),
            local_created_at: timezoneUtils.utcToLocal(task.created_at)
        };

        res.json(pakistanTask);
    } catch (err) {
        console.error('Task creation error:', err);
        res.status(500).json({ error: 'Failed to create task: ' + err.message });
    }
});

// Update task with timezone handling
app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
    const taskId = req.params.id;
    const { title, description, priority, status, progress_percent, notes, time_spent, due_date } = req.body;
    const userId = req.user.userId;

    let updateFields = [];
    let updateValues = [];
    let paramCount = 1;

    if (title) { updateFields.push(`title = $${paramCount++}`); updateValues.push(title); }
    if (description) { updateFields.push(`description = $${paramCount++}`); updateValues.push(description); }
    if (priority) { updateFields.push(`priority = $${paramCount++}`); updateValues.push(priority); }
    if (status) { updateFields.push(`status = $${paramCount++}`); updateValues.push(status); }
    if (time_spent !== undefined) { updateFields.push(`time_spent = $${paramCount++}`); updateValues.push(time_spent); }
    if (progress_percent !== undefined) { updateFields.push(`progress_percent = $${paramCount++}`); updateValues.push(progress_percent); }
    
    // Handle due_date update with timezone conversion
    if (due_date) {
        const utcDueDate = timezoneUtils.localToUTC(due_date);
        updateFields.push(`due_date = $${paramCount++}`);
        updateValues.push(utcDueDate);
    }

    if (status === 'completed') {
        updateFields.push(`completed_at = $${paramCount++}`);
        updateValues.push(new Date());
    }

    updateValues.push(taskId);

    if (updateFields.length > 0) {
        try {
            await pool.query(
                `UPDATE tasks SET ${updateFields.join(', ')} WHERE id = $${paramCount}`,
                updateValues
            );

            // If progress update is provided, also save in progress history
            if (progress_percent !== undefined) {
                await pool.query(
                    'INSERT INTO task_progress (task_id, user_id, progress_percent, notes) VALUES ($1, $2, $3, $4)',
                    [taskId, userId, progress_percent, notes || '']
                );
            }

            res.json({ message: 'Task updated successfully' });
        } catch (err) {
            console.error('Task update error:', err);
            res.status(500).json({ error: 'Failed to update task' });
        }
    } else {
        res.status(400).json({ error: 'No fields to update' });
    }
});

// Delete task
app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
    const taskId = req.params.id;
    const userId = req.user.userId;

    try {
        // First check if task exists and user has permission
        const taskResult = await pool.query('SELECT * FROM tasks WHERE id = $1', [taskId]);
        
        if (taskResult.rows.length === 0) {
            return res.status(404).json({ error: 'Task not found' });
        }

        const task = taskResult.rows[0];

        // Only manager or assigned user can delete
        if (req.user.role !== 'manager' && task.assigned_to !== userId) {
            return res.status(403).json({ error: 'Access denied' });
        }

        await pool.query('DELETE FROM tasks WHERE id = $1', [taskId]);
        res.json({ message: 'Task deleted successfully' });
    } catch (err) {
        console.error('Task delete error:', err);
        res.status(500).json({ error: 'Failed to delete task' });
    }
});

// Get task progress history with timezone conversion
app.get('/api/tasks/:id/progress', authenticateToken, async (req, res) => {
    const taskId = req.params.id;

    try {
        const result = await pool.query(
            `SELECT tp.*, u.name as user_name, u.email as user_email
             FROM task_progress tp 
             JOIN users u ON tp.user_id = u.id 
             WHERE tp.task_id = $1 
             ORDER BY tp.created_at DESC`,
            [taskId]
        );

        // Convert UTC times to Pakistan time
        const progressWithLocalTime = result.rows.map(progress => ({
            ...progress,
            created_at: timezoneUtils.formatForDisplay(timezoneUtils.utcToLocal(progress.created_at)),
            local_created_at: timezoneUtils.utcToLocal(progress.created_at)
        }));

        res.json(progressWithLocalTime);
    } catch (err) {
        console.error('Progress fetch error:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// ==================== HOLIDAY ROUTES ====================

// Get all holidays
app.get('/api/holidays', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT h.*, u.name as created_by_name 
             FROM holidays h 
             LEFT JOIN users u ON h.created_by = u.id 
             ORDER BY h.date ASC`
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Holidays fetch error:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// Create holiday (manager only)
app.post('/api/holidays', authenticateToken, async (req, res) => {
    if (req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Only managers can create holidays' });
    }

    const { date, title, description, type } = req.body;
    const created_by = req.user.userId;

    if (!date || !title) {
        return res.status(400).json({ error: 'Date and title are required' });
    }

    try {
        // Check if holiday already exists for this date
        const existingResult = await pool.query('SELECT id FROM holidays WHERE date = $1', [date]);
        
        if (existingResult.rows.length > 0) {
            return res.status(400).json({ error: 'Holiday already exists for this date' });
        }

        // Create new holiday
        const result = await pool.query(
            `INSERT INTO holidays (date, title, description, type, created_by) 
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [date, title, description, type || 'holiday', created_by]
        );

        // Get the created holiday with creator name
        const holidayResult = await pool.query(
            `SELECT h.*, u.name as created_by_name 
             FROM holidays h 
             LEFT JOIN users u ON h.created_by = u.id 
             WHERE h.id = $1`,
            [result.rows[0].id]
        );

        res.json(holidayResult.rows[0]);
    } catch (err) {
        console.error('Holiday creation error:', err);
        res.status(500).json({ error: 'Failed to create holiday' });
    }
});

// Update holiday (manager only)
app.put('/api/holidays/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Only managers can update holidays' });
    }

    const holidayId = req.params.id;
    const { date, title, description, type } = req.body;

    let updateFields = [];
    let updateValues = [];
    let paramCount = 1;

    if (date) { updateFields.push(`date = $${paramCount++}`); updateValues.push(date); }
    if (title) { updateFields.push(`title = $${paramCount++}`); updateValues.push(title); }
    if (description) { updateFields.push(`description = $${paramCount++}`); updateValues.push(description); }
    if (type) { updateFields.push(`type = $${paramCount++}`); updateValues.push(type); }

    updateValues.push(holidayId);

    if (updateFields.length === 0) {
        return res.status(400).json({ error: 'No fields to update' });
    }

    try {
        const result = await pool.query(
            `UPDATE holidays SET ${updateFields.join(', ')} WHERE id = $${paramCount}`,
            updateValues
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Holiday not found' });
        }

        res.json({ message: 'Holiday updated successfully' });
    } catch (err) {
        console.error('Holiday update error:', err);
        res.status(500).json({ error: 'Failed to update holiday' });
    }
});

// Delete holiday (manager only)
app.delete('/api/holidays/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Only managers can delete holidays' });
    }

    const holidayId = req.params.id;

    try {
        const result = await pool.query('DELETE FROM holidays WHERE id = $1', [holidayId]);
        
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Holiday not found' });
        }

        res.json({ message: 'Holiday deleted successfully' });
    } catch (err) {
        console.error('Holiday delete error:', err);
        res.status(500).json({ error: 'Failed to delete holiday' });
    }
});

// ==================== TASK HISTORY ROUTES ====================

// Get task history for a specific date with timezone
app.get('/api/tasks/history', authenticateToken, async (req, res) => {
    const { date } = req.query;

    if (!date) {
        return res.status(400).json({ error: 'Date parameter is required' });
    }

    // Format date for PostgreSQL query (YYYY-MM-DD) - use local date
    const formattedDate = moment(date).format('YYYY-MM-DD');

    try {
        const employeeResult = await pool.query(
            `SELECT 
                u.id as employee_id,
                u.name as employee_name,
                COUNT(t.id) as total_tasks
            FROM users u
            LEFT JOIN tasks t ON u.id = t.assigned_to AND DATE(t.due_date) = $1
            WHERE u.role = 'employee'
            GROUP BY u.id, u.name
            HAVING COUNT(t.id) > 0
            ORDER BY u.name`,
            [formattedDate]
        );

        if (employeeResult.rows.length === 0) {
            return res.json([]);
        }

        // Get tasks for each employee
        const employeeIds = employeeResult.rows.map(emp => emp.employee_id);
        const placeholders = employeeIds.map((_, i) => `$${i + 2}`).join(',');

        const taskResult = await pool.query(
            `SELECT 
                t.*,
                u.name as assigned_to_name
            FROM tasks t
            LEFT JOIN users u ON t.assigned_to = u.id
            WHERE t.assigned_to IN (${placeholders}) AND DATE(t.due_date) = $1
            ORDER BY t.assigned_to, t.due_date`,
            [formattedDate, ...employeeIds]
        );

        // Convert UTC times to Pakistan time
        const tasksWithLocalTime = taskResult.rows.map(task => ({
            ...task,
            due_date: timezoneUtils.formatForDateTimeInput(timezoneUtils.utcToLocal(task.due_date)),
            created_at: timezoneUtils.formatForDisplay(timezoneUtils.utcToLocal(task.created_at)),
            local_due_date: timezoneUtils.utcToLocal(task.due_date)
        }));

        // Group tasks by employee
        const tasksByEmployee = {};
        tasksWithLocalTime.forEach(task => {
            if (!tasksByEmployee[task.assigned_to]) {
                tasksByEmployee[task.assigned_to] = [];
            }
            tasksByEmployee[task.assigned_to].push(task);
        });

        // Combine employee data with their tasks
        const formattedResults = employeeResult.rows.map(employee => ({
            employee_id: employee.employee_id,
            employee_name: employee.employee_name,
            total_tasks: employee.total_tasks,
            tasks: tasksByEmployee[employee.employee_id] || []
        }));

        res.json(formattedResults);
    } catch (err) {
        console.error('Task history fetch error:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// Get employee task statistics
app.get('/api/employees/stats', authenticateToken, async (req, res) => {
    if (req.user.role !== 'manager') {
        return res.status(403).json({ error: 'Access denied' });
    }

    try {
        const result = await pool.query(
            `SELECT 
                u.id,
                u.name,
                u.email,
                COUNT(t.id) as total_tasks,
                SUM(CASE WHEN t.status = 'completed' THEN 1 ELSE 0 END) as completed_tasks,
                SUM(CASE WHEN t.status = 'pending' THEN 1 ELSE 0 END) as pending_tasks,
                SUM(CASE WHEN t.status = 'in_progress' THEN 1 ELSE 0 END) as in_progress_tasks,
                SUM(CASE WHEN t.status = 'overdue' THEN 1 ELSE 0 END) as overdue_tasks,
                AVG(t.progress_percent) as avg_progress
            FROM users u
            LEFT JOIN tasks t ON u.id = t.assigned_to
            WHERE u.role = 'employee'
            GROUP BY u.id, u.name, u.email
            ORDER BY u.name`
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Employee stats fetch error:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// ==================== CALENDAR ROUTES ====================

// Calendar events with timezone handling
app.get('/api/calendar/events', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const userRole = req.user.role;

    try {
        let query = `
            SELECT 
                id,
                title,
                due_date as start,
                due_date as end,
                priority,
                status,
                assigned_to,
                'task' as type
            FROM tasks
        `;

        const params = [];

        if (userRole === 'employee') {
            query += ' WHERE assigned_to = $1';
            params.push(userId);
        }

        query += ' ORDER BY due_date ASC';

        const result = await pool.query(query, params);
        
        // Convert UTC times to Pakistan time for calendar
        const events = result.rows.map(event => {
            const pakistanStart = timezoneUtils.utcToLocal(event.start);
            const pakistanEnd = timezoneUtils.utcToLocal(event.end);
            
            return {
                id: event.id,
                title: event.title,
                start: pakistanStart,
                end: pakistanEnd,
                priority: event.priority,
                status: event.status,
                assigned_to: event.assigned_to,
                type: event.type,
                color: getEventColor(event.priority, event.status),
                local_start: pakistanStart,
                local_end: pakistanEnd
            };
        });

        res.json(events);
    } catch (err) {
        console.error('Calendar events error:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// Helper function to get event color based on priority and status
function getEventColor(priority, status) {
    if (status === 'completed') return '#10B981'; // Green
    if (status === 'overdue') return '#EF4444'; // Red
    
    switch (priority) {
        case 'high':
            return '#EF4444'; // Red
        case 'medium':
            return '#F59E0B'; // Yellow
        case 'low':
            return '#3B82F6'; // Blue
        default:
            return '#6B7280'; // Gray
    }
}

// Get calendar data (tasks + holidays) with timezone
app.get('/api/calendar/data', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const userRole = req.user.role;

    try {
        // Get tasks
        let taskQuery = `
            SELECT 
                id,
                title,
                due_date as start,
                due_date as end,
                priority,
                status,
                assigned_to,
                'task' as type
            FROM tasks
        `;

        const params = [];

        if (userRole === 'employee') {
            taskQuery += ' WHERE assigned_to = $1';
            params.push(userId);
        }

        const taskResult = await pool.query(taskQuery, params);

        // Get holidays (all users can see holidays)
        const holidayResult = await pool.query(`
            SELECT 
                id,
                title,
                date as start,
                date as end,
                'holiday' as type,
                description
            FROM holidays
            ORDER BY date ASC
        `);

        // Convert task UTC times to Pakistan time
        const tasksWithLocalTime = taskResult.rows.map(task => {
            const pakistanStart = timezoneUtils.utcToLocal(task.start);
            const pakistanEnd = timezoneUtils.utcToLocal(task.end);
            
            return {
                ...task,
                start: pakistanStart,
                end: pakistanEnd,
                local_start: pakistanStart,
                local_end: pakistanEnd
            };
        });

        // Combine tasks and holidays
        const events = [...tasksWithLocalTime, ...holidayResult.rows];
        
        // Add colors to events
        const eventsWithColors = events.map(event => ({
            ...event,
            color: event.type === 'holiday' ? '#8B5CF6' : getEventColor(event.priority, event.status),
            textColor: '#FFFFFF'
        }));

        res.json(eventsWithColors);
    } catch (err) {
        console.error('Calendar data error:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// Get calendar events with filters and timezone
app.get('/api/calendar/events/filter', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    const userRole = req.user.role;
    const { start, end, type } = req.query;

    try {
        let taskQuery = `
            SELECT 
                id,
                title,
                due_date as start,
                due_date as end,
                priority,
                status,
                assigned_to,
                'task' as type,
                description
            FROM tasks
            WHERE 1=1
        `;

        const params = [];
        let paramCount = 1;

        if (userRole === 'employee') {
            taskQuery += ` AND assigned_to = $${paramCount++}`;
            params.push(userId);
        }

        if (start) {
            taskQuery += ` AND due_date >= $${paramCount++}`;
            params.push(start);
        }

        if (end) {
            taskQuery += ` AND due_date <= $${paramCount++}`;
            params.push(end);
        }

        if (type && type !== 'all') {
            taskQuery += ` AND priority = $${paramCount++}`;
            params.push(type);
        }

        taskQuery += ' ORDER BY due_date ASC';

        const taskResult = await pool.query(taskQuery, params);

        // Get holidays if not filtered or type is holiday
        let holidayQuery = `
            SELECT 
                id,
                title,
                date as start,
                date as end,
                'holiday' as type,
                description
            FROM holidays
            WHERE 1=1
        `;

        const holidayParams = [];
        let holidayParamCount = 1;

        if (start) {
            holidayQuery += ` AND date >= $${holidayParamCount++}`;
            holidayParams.push(start);
        }

        if (end) {
            holidayQuery += ` AND date <= $${holidayParamCount++}`;
            holidayParams.push(end);
        }

        holidayQuery += ' ORDER BY date ASC';

        const holidayResult = await pool.query(holidayQuery, holidayParams);

        // Convert task UTC times to Pakistan time
        const tasksWithLocalTime = taskResult.rows.map(task => {
            const pakistanStart = timezoneUtils.utcToLocal(task.start);
            const pakistanEnd = timezoneUtils.utcToLocal(task.end);
            
            return {
                ...task,
                start: pakistanStart,
                end: pakistanEnd,
                local_start: pakistanStart,
                local_end: pakistanEnd
            };
        });

        // Combine events based on type filter
        let events = [];
        if (!type || type === 'all' || type === 'task') {
            events = [...events, ...tasksWithLocalTime];
        }
        if (!type || type === 'all' || type === 'holiday') {
            events = [...events, ...holidayResult.rows];
        }

        // Add colors to events
        const eventsWithColors = events.map(event => ({
            ...event,
            color: event.type === 'holiday' ? '#8B5CF6' : getEventColor(event.priority, event.status),
            textColor: '#FFFFFF'
        }));

        res.json(eventsWithColors);
    } catch (err) {
        console.error('Calendar events filter error:', err);
        res.status(500).json({ error: 'Database error' });
    }
});

// Timezone info endpoint
app.get('/api/timezone', (req, res) => {
    res.json({
        server_timezone: process.env.TZ,
        current_pakistan_time: timezoneUtils.getCurrentTime(),
        timestamp: new Date().toISOString(),
        timezone_offset: '+05:00'
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        message: '🚀 Task Manager API is running!',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        endpoints: {
            health: '/api/health',
            test: '/api/test',
            timezone: '/api/timezone',
            login: '/api/login',
            tasks: '/api/tasks',
            calendar: '/api/calendar/events'
        }
    });
});

// Start server
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`🚀 Server running on port ${PORT}`);
        console.log(`⏰ Server Timezone: ${process.env.TZ}`);
        console.log(`🕒 Current Pakistan Time: ${timezoneUtils.getCurrentTime()}`);
        console.log(`📊 API endpoints available at /api`);
    });
}

module.exports = app;