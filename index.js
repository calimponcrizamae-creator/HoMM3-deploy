const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const redis = require('redis');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// ============================================
// KONFIGURACJA
// ============================================
const CONFIG = {
    PORT: process.env.PORT || 3000,
    JWT_SECRET: process.env.JWT_SECRET || 'homm3-zlota-edycja-secret-key-2026',
    JWT_EXPIRES: '7d',
    TURN_DURATION: 600, // 10 minut w sekundach
    MAX_PLAYERS: 10000,
    MAP_SIZE: 5000,
    CHUNK_SIZE: 100,
    DB_CONFIG: {
        host: process.env.DB_HOST || 'localhost',
        port: process.env.DB_PORT || 5432,
        database: process.env.DB_NAME || 'homm3_online',
        user: process.env.DB_USER || 'homm3_user',
        password: process.env.DB_PASSWORD || 'homm3_pass',
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000,
    },
    REDIS_CONFIG: {
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
    }
};

// ============================================
// INICJALIZACJA
// ============================================
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: '*',
        methods: ['GET', 'POST']
    },
    pingTimeout: 60000,
    pingInterval: 25000
});

const pgPool = new Pool(CONFIG.DB_CONFIG);
const redisClient = redis.createClient(CONFIG.REDIS_CONFIG);

redisClient.on('error', (err) => {
    console.warn('Redis error:', err.message || err);
});
redisClient.on('connect', () => {
    console.log('Redis connected');
});
redisClient.on('ready', () => {
    console.log('Redis ready');
});
redisClient.on('end', () => {
    console.log('Redis connection closed');
});

pgPool.on('error', (err) => {
    console.error('Postgres pool error:', err);
});

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Zbyt wiele żądań, spróbuj później.'
});
app.use('/api/', limiter);

app.get('/', (req, res) => {
    res.json({ message: 'HoMM3-deploy backend is running' });
});

app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

// ============================================
// MODELE DANYCH
// ============================================

class User {
    constructor(data) {
        this.id = data.id;
        this.username = data.username;
        this.email = data.email;
        this.password_hash = data.password_hash;
        this.created_at = data.created_at;
        this.last_login = data.last_login;
        this.is_active = data.is_active;
        this.rank = data.rank || 1000;
        this.games_played = data.games_played || 0;
        this.games_won = data.games_won || 0;
        this.favorite_faction = data.favorite_faction;
    }

    toJSON() {
        return {
            id: this.id,
            username: this.username,
            email: this.email,
            rank: this.rank,
            games_played: this.games_played,
            games_won: this.games_won,
            favorite_faction: this.favorite_faction
        };
    }
}

class Hero {
    constructor(data) {
        this.id = data.id;
        this.player_id = data.player_id;
        this.name = data.name;
        this.faction = data.faction;
        this.level = data.level || 1;
        this.experience = data.experience || 0;
        this.attack = data.attack || 1;
        this.defense = data.defense || 1;
        this.spell_power = data.spell_power || 1;
        this.knowledge = data.knowledge || 1;
        this.secondary_skills = data.secondary_skills || [];
        this.army = data.army || [];
        this.position_x = data.position_x || 0;
        this.position_y = data.position_y || 0;
        this.layer = data.layer || 'surface';
        this.movement_points = data.movement_points || 2000;
        this.mana = data.mana || 10;
        this.max_mana = data.max_mana || 10;
        this.artifacts = data.artifacts || [];
        this.spells = data.spells || [];
    }
}

class Castle {
    constructor(data) {
        this.id = data.id;
        this.player_id = data.player_id;
        this.name = data.name;
        this.faction = data.faction;
        this.position_x = data.position_x;
        this.position_y = data.position_y;
        this.layer = data.layer || 'surface';
        this.buildings = data.buildings || [];
        this.garrison = data.garrison || [];
        this.income = data.income || 500;
        this.mage_guild_level = data.mage_guild_level || 0;
    }
}

// ============================================
// SYSTEM AUTORYZACJI
// ============================================

const generateToken = (userId) => {
    return jwt.sign({ userId }, CONFIG.JWT_SECRET, { expiresIn: CONFIG.JWT_EXPIRES });
};

const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Brak tokenu autoryzacyjnego' });
    }

    try {
        const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
        const result = await pgPool.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Użytkownik nie istnieje' });
        }
        req.user = new User(result.rows[0]);
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Nieprawidłowy token' });
    }
};

// ============================================
// API ROUTES
// ============================================

// Rejestracja
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, favoriteFaction } = req.body;

        // Walidacja
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Wszystkie pola są wymagane' });
        }

        if (username.length < 3 || username.length > 32) {
            return res.status(400).json({ error: 'Nazwa użytkownika musi mieć 3-32 znaki' });
        }

        if (password.length < 8) {
            return res.status(400).json({ error: 'Hasło musi mieć minimum 8 znaków' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Nieprawidłowy format email' });
        }

        // Sprawdź czy użytkownik istnieje
        const existingUser = await pgPool.query(
            'SELECT * FROM users WHERE username = $1 OR email = $2',
            [username, email]
        );

        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: 'Użytkownik lub email już istnieje' });
        }

        // Hash hasła
        const hashedPassword = await bcrypt.hash(password, 12);

        // Stwórz użytkownika
        const result = await pgPool.query(
            `INSERT INTO users (username, email, password_hash, favorite_faction, rank) 
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [username, email, hashedPassword, favoriteFaction || null, 1000]
        );

        const user = new User(result.rows[0]);
        const token = generateToken(user.id);

        // Stwórz początkowy stan gry
        await pgPool.query(
            `INSERT INTO game_sessions (player_id, resources) 
             VALUES ($1, $2)`,
            [user.id, JSON.stringify({
                gold: 10000, wood: 20, ore: 20,
                crystal: 5, gems: 5, mercury: 5, sulfur: 5
            })]
        );

        res.status(201).json({
            message: 'Rejestracja udana',
            token,
            user: user.toJSON()
        });

    } catch (error) {
        console.error('Błąd rejestracji:', error);
        res.status(500).json({ error: 'Wewnętrzny błąd serwera' });
    }
});

// Logowanie
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Wszystkie pola są wymagane' });
        }

        const result = await pgPool.query(
            'SELECT * FROM users WHERE username = $1 OR email = $1',
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Nieprawidłowe dane logowania' });
        }

        const user = new User(result.rows[0]);
        const validPassword = await bcrypt.compare(password, user.password_hash);

        if (!validPassword) {
            return res.status(401).json({ error: 'Nieprawidłowe dane logowania' });
        }

        // Aktualizuj last_login
        await pgPool.query(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
            [user.id]
        );

        const token = generateToken(user.id);

        res.json({
            message: 'Logowanie udane',
            token,
            user: user.toJSON()
        });

    } catch (error) {
        console.error('Błąd logowania:', error);
        res.status(500).json({ error: 'Wewnętrzny błąd serwera' });
    }
});

// Profil użytkownika
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const gameState = await pgPool.query(
            'SELECT * FROM game_sessions WHERE player_id = $1',
            [req.user.id]
        );

        const heroes = await pgPool.query(
            'SELECT * FROM heroes WHERE player_id = $1',
            [req.user.id]
        );

        const castles = await pgPool.query(
            'SELECT * FROM castles WHERE player_id = $1',
            [req.user.id]
        );

        res.json({
            user: req.user.toJSON(),
            gameState: gameState.rows[0] || null,
            heroes: heroes.rows,
            castles: castles.rows
        });
    } catch (error) {
        console.error('Błąd profilu:', error);
        res.status(500).json({ error: 'Wewnętrzny błąd serwera' });
    }
});

// Ranking graczy
app.get('/api/ranking', async (req, res) => {
    try {
        const { limit = 100, offset = 0 } = req.query;

        const result = await pgPool.query(
            `SELECT id, username, rank, games_played, games_won, 
                    ROUND(games_won::numeric / NULLIF(games_played, 0) * 100, 2) as win_rate
             FROM users 
             WHERE is_active = true
             ORDER BY rank DESC, games_won DESC
             LIMIT $1 OFFSET $2`,
            [limit, offset]
        );

        res.json({
            players: result.rows,
            total: result.rows.length
        });
    } catch (error) {
        console.error('Błąd rankingu:', error);
        res.status(500).json({ error: 'Wewnętrzny błąd serwera' });
    }
});

// ============================================
// SYSTEM MAPY
// ============================================

class MapManager {
    constructor() {
        this.chunkCache = new Map();
        this.chunkSize = CONFIG.CHUNK_SIZE;
        this.mapSize = CONFIG.MAP_SIZE;
    }

    getChunkKey(x, y, layer) {
        const chunkX = Math.floor(x / this.chunkSize);
        const chunkY = Math.floor(y / this.chunkSize);
        return `${layer}:${chunkX}:${chunkY}`;
    }

    async getChunk(x, y, layer) {
        const key = this.getChunkKey(x, y, layer);

        if (this.chunkCache.has(key)) {
            return this.chunkCache.get(key);
        }

        const chunkX = Math.floor(x / this.chunkSize);
        const chunkY = Math.floor(y / this.chunkSize);

        const result = await pgPool.query(
            'SELECT * FROM map_chunks WHERE chunk_x = $1 AND chunk_y = $2 AND layer = $3',
            [chunkX, chunkY, layer]
        );

        if (result.rows.length > 0) {
            const chunk = result.rows[0];
            this.chunkCache.set(key, chunk);
            return chunk;
        }

        const newChunk = await this.generateChunk(chunkX, chunkY, layer);
        return newChunk;
    }

    async generateChunk(chunkX, chunkY, layer) {
        const terrain = [];
        const objects = [];

        for (let localY = 0; localY < this.chunkSize; localY++) {
            for (let localX = 0; localX < this.chunkSize; localX++) {
                const globalX = chunkX * this.chunkSize + localX;
                const globalY = chunkY * this.chunkSize + localY;

                const terrainType = this.determineTerrain(globalX, globalY, layer);
                terrain.push({
                    x: globalX,
                    y: globalY,
                    type: terrainType
                });

                if (Math.random() < 0.02) {
                    objects.push(this.generateObject(globalX, globalY, terrainType));
                }
            }
        }

        const chunk = {
            chunk_x: chunkX,
            chunk_y: chunkY,
            layer,
            terrain_data: Buffer.from(JSON.stringify(terrain)),
            objects: JSON.stringify(objects)
        };

        await pgPool.query(
            `INSERT INTO map_chunks (chunk_x, chunk_y, layer, terrain_data, objects) 
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (chunk_x, chunk_y, layer) DO UPDATE SET
             terrain_data = EXCLUDED.terrain_data,
             objects = EXCLUDED.objects`,
            [chunkX, chunkY, layer, chunk.terrain_data, chunk.objects]
        );

        return chunk;
    }

    determineTerrain(x, y, layer) {
        if (layer === 'underground') {
            return 'SUBTERRANEAN';
        }

        const noise = Math.sin(x * 0.01) * Math.cos(y * 0.01) +
                      Math.sin(x * 0.05) * Math.cos(y * 0.05) * 0.5;

        if (noise < -0.5) return 'WATER';
        if (noise < -0.3) return 'SAND';
        if (noise < 0) return 'GRASS';
        if (noise < 0.3) return 'DIRT';
        if (noise < 0.5) return 'ROUGH';
        if (noise < 0.7) return 'SNOW';
        if (noise < 0.8) return 'SWAMP';
        return 'LAVA';
    }

    generateObject(x, y, terrainType) {
        const objectTypes = ['RESOURCE', 'ARTIFACT', 'MONSTER', 'MINE', 'DWELLING'];
        const type = objectTypes[Math.floor(Math.random() * objectTypes.length)];

        return {
            x, y, type,
            id: `obj_${x}_${y}_${Date.now()}`,
            data: this.generateObjectData(type, terrainType)
        };
    }

    generateObjectData(type, terrainType) {
        switch(type) {
            case 'RESOURCE':
                const resources = ['gold', 'wood', 'ore', 'crystal', 'gems', 'mercury', 'sulfur'];
                return {
                    resource: resources[Math.floor(Math.random() * resources.length)],
                    amount: Math.floor(Math.random() * 1000) + 100
                };
            case 'MONSTER':
                return {
                    faction: ['CASTLE', 'RAMPART', 'TOWER', 'INFERNO', 'NECROPOLIS', 'DUNGEON', 'STRONGHOLD', 'FORTRESS', 'CONFLUX'][Math.floor(Math.random() * 9)],
                    tier: Math.floor(Math.random() * 7) + 1,
                    count: Math.floor(Math.random() * 50) + 10
                };
            default:
                return {};
        }
    }
}

const mapManager = new MapManager();

// API Mapy
app.get('/api/map/chunk', authenticateToken, async (req, res) => {
    try {
        const { x, y, layer = 'surface' } = req.query;

        if (!x || !y) {
            return res.status(400).json({ error: 'Wymagane parametry x i y' });
        }

        const chunk = await mapManager.getChunk(parseInt(x), parseInt(y), layer);

        res.json({
            chunk_x: chunk.chunk_x,
            chunk_y: chunk.chunk_y,
            layer: chunk.layer,
            terrain: JSON.parse(chunk.terrain_data.toString()),
            objects: JSON.parse(chunk.objects)
        });
    } catch (error) {
        console.error('Błąd mapy:', error);
        res.status(500).json({ error: 'Wewnętrzny błąd serwera' });
    }
});

// ============================================
// SYSTEM TUR (WebSocket)
// ============================================

class TurnManager {
    constructor() {
        this.players = new Map();
        this.playerQueue = [];
        this.currentPlayerIndex = 0;
        this.turnTimer = null;
        this.turnStartTime = null;
        this.currentTurn = 1;
        this.gamePhase = 'HERO_MOVEMENT';
        this.turnDuration = CONFIG.TURN_DURATION;
    }

    addPlayer(playerId, playerData) {
        this.players.set(playerId, {
            id: playerId,
            name: playerData.username,
            socket: playerData.socket,
            isActive: true,
            turnTimeUsed: 0
        });
        this.playerQueue.push(playerId);
    }

    removePlayer(playerId) {
        this.players.delete(playerId);
        const index = this.playerQueue.indexOf(playerId);
        if (index > -1) {
            this.playerQueue.splice(index, 1);
            if (index <= this.currentPlayerIndex && this.currentPlayerIndex > 0) {
                this.currentPlayerIndex--;
            }
        }
    }

    startGame() {
        if (this.playerQueue.length === 0) return;

        this.currentTurn = 1;
        this.currentPlayerIndex = 0;
        this.startTurn();
    }

    startTurn() {
        if (this.playerQueue.length === 0) return;

        const playerId = this.playerQueue[this.currentPlayerIndex];
        const player = this.players.get(playerId);

        if (!player || !player.isActive) {
            this.nextTurn();
            return;
        }

        this.turnStartTime = Date.now();
        this.gamePhase = 'HERO_MOVEMENT';

        player.socket.emit('YOUR_TURN', {
            turnNumber: this.currentTurn,
            timeRemaining: this.turnDuration,
            phase: this.gamePhase,
            message: 'Twoja tura! Masz 10 minut.'
        });

        io.emit('TURN_CHANGED', {
            currentPlayer: {
                id: playerId,
                name: player.name
            },
            turnNumber: this.currentTurn,
            timeRemaining: this.turnDuration,
            phase: this.gamePhase
        });

        this.turnTimer = setTimeout(() => {
            this.endTurn();
        }, this.turnDuration * 1000);

        setTimeout(() => {
            if (this.currentPlayer() === playerId) {
                player.socket.emit('TURN_WARNING', {
                    timeRemaining: 120,
                    message: 'Pozostało 2 minuty!'
                });
            }
        }, (this.turnDuration - 120) * 1000);
    }

    currentPlayer() {
        if (this.playerQueue.length === 0) return null;
        return this.playerQueue[this.currentPlayerIndex];
    }

    endTurn() {
        clearTimeout(this.turnTimer);

        const playerId = this.playerQueue[this.currentPlayerIndex];
        const player = this.players.get(playerId);

        if (player) {
            player.socket.emit('TURN_ENDED', {
                message: 'Twoja tura się zakończyła.'
            });
        }

        this.nextTurn();
    }

    nextTurn() {
        this.currentPlayerIndex = (this.currentPlayerIndex + 1) % this.playerQueue.length;

        if (this.currentPlayerIndex === 0) {
            this.currentTurn++;
        }

        this.startTurn();
    }

    getRemainingTime() {
        if (!this.turnStartTime) return 0;
        const elapsed = (Date.now() - this.turnStartTime) / 1000;
        return Math.max(0, this.turnDuration - elapsed);
    }

    forceEndTurn(playerId) {
        if (this.currentPlayer() === playerId) {
            this.endTurn();
        }
    }
}

const turnManager = new TurnManager();

// ============================================
// SYSTEM WALKI
// ============================================

class CombatManager {
    constructor() {
        this.activeBattles = new Map();
    }

    createBattle(attackerId, defenderId, attackerHero, defenderHero) {
        const battleId = `battle_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        const battle = {
            id: battleId,
            attackerId,
            defenderId,
            attackerHero,
            defenderHero,
            phase: 'SETUP',
            round: 1,
            turn: attackerId,
            battlefield: this.generateBattlefield(),
            attackerArmy: [...attackerHero.army],
            defenderArmy: [...defenderHero.army],
            log: [],
            startedAt: Date.now()
        };

        this.activeBattles.set(battleId, battle);
        return battle;
    }

    generateBattlefield() {
        const battlefield = [];
        for (let y = 0; y < 11; y++) {
            const row = [];
            for (let x = 0; x < 15; x++) {
                row.push({
                    x, y,
                    type: 'EMPTY',
                    unit: null,
                    obstacle: Math.random() < 0.05 ? this.getRandomObstacle() : null
                });
            }
            battlefield.push(row);
        }
        return battlefield;
    }

    getRandomObstacle() {
        const obstacles = ['ROCK', 'TREE', 'BUSH', 'FIRE', 'WATER'];
        return obstacles[Math.floor(Math.random() * obstacles.length)];
    }

    calculateDamage(attacker, defender, attackerHero, defenderHero, distance = 0) {
        let baseDamage = 0;

        if (attacker.count <= 10) {
            for (let i = 0; i < attacker.count; i++) {
                baseDamage += Math.floor(Math.random() * (attacker.damage_max - attacker.damage_min + 1)) + attacker.damage_min;
            }
        } else {
            let sampleDamage = 0;
            for (let i = 0; i < 10; i++) {
                sampleDamage += Math.floor(Math.random() * (attacker.damage_max - attacker.damage_min + 1)) + attacker.damage_min;
            }
            baseDamage = Math.floor(sampleDamage * (attacker.count / 10));
        }

        let I1 = 0, I2 = 0, I3 = 0, I4 = 0, I5 = 0;

        const attackTotal = attacker.attack + (attackerHero ? attackerHero.attack : 0);
        const defenseTotal = defender.defense + (defenderHero ? defenderHero.defense : 0);

        if (attackTotal > defenseTotal) {
            I1 = Math.min(0.05 * (attackTotal - defenseTotal), 3.0);
        }

        if (attacker.ranged && attackerHero && attackerHero.secondary_skills.includes('Archery')) {
            const archeryLevel = attackerHero.secondary_skills.indexOf('Archery');
            I2 = [0, 0.10, 0.25, 0.50][archeryLevel + 1] || 0;
        }

        if (Math.random() < 0.0833) {
            I4 = 1.00;
        }

        if (attacker.name === 'Cavalier' || attacker.name === 'Champion') {
            I5 = 0.05 * distance;
        }

        let R1 = 0, R2 = 0, R3 = 0, R4 = 0, R5 = 0, R6 = 0, R7 = 0, R8 = 0;

        if (defenseTotal > attackTotal) {
            R1 = Math.min(0.025 * (defenseTotal - attackTotal), 0.70);
        }

        if (defenderHero && defenderHero.secondary_skills.includes('Armorer')) {
            const armorerLevel = defenderHero.secondary_skills.indexOf('Armorer');
            R2 = [0, 0.05, 0.10, 0.15][armorerLevel + 1] || 0;
        }

        const damage = Math.floor(
            baseDamage * 
            (1 + I1 + I2 + I3 + I4 + I5) * 
            (1 - R1) * 
            (1 - R2 - R3) * 
            (1 - R4) * 
            (1 - R5) * 
            (1 - R6) * 
            (1 - R7) * 
            (1 - R8)
        );

        return Math.max(1, damage);
    }

    processAction(battleId, playerId, action) {
        const battle = this.activeBattles.get(battleId);
        if (!battle) return { error: 'Bitwa nie istnieje' };

        if (battle.turn !== playerId) {
            return { error: 'To nie twoja tura' };
        }

        switch(action.type) {
            case 'MOVE':
                return this.processMove(battle, action);
            case 'ATTACK':
                return this.processAttack(battle, action);
            case 'CAST_SPELL':
                return this.processSpell(battle, action);
            case 'WAIT':
                return this.processWait(battle, action);
            case 'DEFEND':
                return this.processDefend(battle, action);
            case 'SURRENDER':
                return this.processSurrender(battle, action);
            default:
                return { error: 'Nieznana akcja' };
        }
    }

    processAttack(battle, action) {
        const { attackerId, defenderId } = action;

        const attackerArmy = battle.attackerId === battle.turn ? battle.attackerArmy : battle.defenderArmy;
        const defenderArmy = battle.attackerId === battle.turn ? battle.defenderArmy : battle.attackerArmy;

        const attacker = attackerArmy.find(u => u.id === attackerId);
        const defender = defenderArmy.find(u => u.id === defenderId);

        if (!attacker || !defender) {
            return { error: 'Jednostka nie znaleziona' };
        }

        const damage = this.calculateDamage(
            attacker, defender,
            battle.attackerId === battle.turn ? battle.attackerHero : battle.defenderHero,
            battle.attackerId === battle.turn ? battle.defenderHero : battle.attackerHero,
            action.distance || 0
        );

        defender.health -= damage;
        const killed = Math.floor(damage / defender.max_health);
        defender.count = Math.max(0, defender.count - killed);

        battle.log.push({
            type: 'ATTACK',
            attacker: attacker.name,
            defender: defender.name,
            damage,
            killed,
            timestamp: Date.now()
        });

        if (defender.count > 0 && defender.retaliations > 0) {
            const retalDamage = this.calculateDamage(
                defender, attacker,
                battle.attackerId === battle.turn ? battle.defenderHero : battle.attackerHero,
                battle.attackerId === battle.turn ? battle.attackerHero : battle.defenderHero
            );
            attacker.health -= retalDamage;
            const retalKilled = Math.floor(retalDamage / attacker.max_health);
            attacker.count = Math.max(0, attacker.count - retalKilled);
            defender.retaliations--;

            battle.log.push({
                type: 'RETALIATION',
                attacker: defender.name,
                defender: attacker.name,
                damage: retalDamage,
                killed: retalKilled
            });
        }

        const attackerAlive = attackerArmy.some(u => u.count > 0);
        const defenderAlive = defenderArmy.some(u => u.count > 0);

        if (!attackerAlive || !defenderAlive) {
            battle.phase = 'FINISHED';
            const winner = attackerAlive ? battle.attackerId : battle.defenderId;
            battle.winner = winner;

            battle.log.push({
                type: 'BATTLE_END',
                winner,
                message: `Bitwa zakończona! Zwycięzca: ${winner}`
            });
        }

        return {
            success: true,
            damage,
            killed,
            battleState: battle
        };
    }

    endBattle(battleId, winner) {
        const battle = this.activeBattles.get(battleId);
        if (!battle) return;

        battle.phase = 'FINISHED';
        battle.winner = winner;
        battle.endedAt = Date.now();

        pgPool.query(
            `INSERT INTO battles (attacker_id, defender_id, result, battle_log, ended_at) 
             VALUES ($1, $2, $3, $4, $5)`,
            [battle.attackerId, battle.defenderId, 
             winner === battle.attackerId ? 'attacker_won' : 'defender_won',
             JSON.stringify(battle.log), new Date()]
        );

        this.activeBattles.delete(battleId);
    }
}

const combatManager = new CombatManager();

// ============================================
// WEBSOCKET HANDLERS
// ============================================

io.on('connection', (socket) => {
    console.log('Nowe połączenie:', socket.id);

    socket.on('AUTHENTICATE', async (token) => {
        try {
            const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
            const result = await pgPool.query('SELECT * FROM users WHERE id = $1', [decoded.userId]);

            if (result.rows.length > 0) {
                socket.userId = decoded.userId;
                socket.user = new User(result.rows[0]);
                socket.join('game');

                turnManager.addPlayer(decoded.userId, {
                    username: socket.user.username,
                    socket: socket
                });

                socket.emit('AUTHENTICATED', {
                    success: true,
                    user: socket.user.toJSON()
                });

                io.emit('PLAYER_JOINED', {
                    playerId: decoded.userId,
                    username: socket.user.username
                });
            }
        } catch (err) {
            socket.emit('AUTHENTICATED', { success: false, error: 'Nieprawidłowy token' });
        }
    });

    socket.on('MOVE_HERO', async (data) => {
        if (!socket.userId) return;

        const { heroId, x, y, layer } = data;

        if (turnManager.currentPlayer() !== socket.userId) {
            socket.emit('ERROR', { message: 'To nie twoja tura!' });
            return;
        }

        try {
            await pgPool.query(
                'UPDATE heroes SET position_x = $1, position_y = $2, layer = $3 WHERE id = $4 AND player_id = $5',
                [x, y, layer, heroId, socket.userId]
            );

            socket.emit('HERO_MOVED', { heroId, x, y, layer });
            socket.to('game').emit('HERO_MOVED', {
                playerId: socket.userId,
                heroId, x, y, layer
            });
        } catch (error) {
            socket.emit('ERROR', { message: 'Błąd ruchu bohatera' });
        }
    });

    socket.on('BUILD_STRUCTURE', async (data) => {
        if (!socket.userId) return;

        const { castleId, buildingId } = data;

        if (turnManager.currentPlayer() !== socket.userId) {
            socket.emit('ERROR', { message: 'To nie twoja tura!' });
            return;
        }

        try {
            const resources = await pgPool.query(
                'SELECT resources FROM game_sessions WHERE player_id = $1',
                [socket.userId]
            );

            const playerResources = resources.rows[0].resources;
            const buildingCost = getBuildingCost(buildingId);

            if (!hasEnoughResources(playerResources, buildingCost)) {
                socket.emit('ERROR', { message: 'Niewystarczające zasoby!' });
                return;
            }

            const newResources = subtractResources(playerResources, buildingCost);

            await pgPool.query(
                'UPDATE game_sessions SET resources = $1 WHERE player_id = $2',
                [JSON.stringify(newResources), socket.userId]
            );

            await pgPool.query(
                'UPDATE castles SET buildings = buildings || $1::jsonb WHERE id = $2',
                [JSON.stringify([buildingId]), castleId]
            );

            socket.emit('STRUCTURE_BUILT', { castleId, buildingId });
            socket.to('game').emit('STRUCTURE_BUILT', {
                playerId: socket.userId,
                castleId, buildingId
            });

        } catch (error) {
            socket.emit('ERROR', { message: 'Błąd budowy' });
        }
    });

    socket.on('RECRUIT_UNITS', async (data) => {
        if (!socket.userId) return;

        const { castleId, unitType, count } = data;

        if (turnManager.currentPlayer() !== socket.userId) {
            socket.emit('ERROR', { message: 'To nie twoja tura!' });
            return;
        }

        try {
            const unitData = getUnitData(unitType);
            const totalCost = multiplyResources(unitData.cost, count);

            const resources = await pgPool.query(
                'SELECT resources FROM game_sessions WHERE player_id = $1',
                [socket.userId]
            );

            if (!hasEnoughResources(resources.rows[0].resources, totalCost)) {
                socket.emit('ERROR', { message: 'Niewystarczające zasoby!' });
                return;
            }

            await pgPool.query(
                'UPDATE castles SET garrison = garrison || $1::jsonb WHERE id = $2',
                [JSON.stringify([{ type: unitType, count }]), castleId]
            );

            socket.emit('UNITS_RECRUITED', { castleId, unitType, count });

        } catch (error) {
            socket.emit('ERROR', { message: 'Błąd rekrutacji' });
        }
    });

    socket.on('START_BATTLE', async (data) => {
        if (!socket.userId) return;

        const { defenderId, attackerHeroId } = data;

        try {
            const attackerHero = await pgPool.query('SELECT * FROM heroes WHERE id = $1', [attackerHeroId]);
            const defenderHero = await pgPool.query('SELECT * FROM heroes WHERE player_id = $1 LIMIT 1', [defenderId]);

            if (attackerHero.rows.length === 0 || defenderHero.rows.length === 0) {
                socket.emit('ERROR', { message: 'Bohater nie znaleziony' });
                return;
            }

            const battle = combatManager.createBattle(
                socket.userId,
                defenderId,
                new Hero(attackerHero.rows[0]),
                new Hero(defenderHero.rows[0])
            );

            socket.emit('BATTLE_STARTED', {
                battleId: battle.id,
                battlefield: battle.battlefield,
                attackerArmy: battle.attackerArmy,
                defenderArmy: battle.defenderArmy
            });

            const defenderSocket = getSocketByPlayerId(defenderId);
            if (defenderSocket) {
                defenderSocket.emit('BATTLE_INVITE', {
                    battleId: battle.id,
                    attacker: socket.user.username,
                    battlefield: battle.battlefield
                });
            }

        } catch (error) {
            socket.emit('ERROR', { message: 'Błąd rozpoczęcia bitwy' });
        }
    });

    socket.on('BATTLE_ACTION', (data) => {
        if (!socket.userId) return;

        const { battleId, action } = data;
        const result = combatManager.processAction(battleId, socket.userId, action);

        if (result.error) {
            socket.emit('ERROR', { message: result.error });
            return;
        }

        const battle = combatManager.activeBattles.get(battleId);
        if (battle) {
            io.to(battleId).emit('BATTLE_UPDATE', {
                battleId,
                log: battle.log,
                attackerArmy: battle.attackerArmy,
                defenderArmy: battle.defenderArmy,
                turn: battle.turn
            });
        }
    });

    socket.on('END_TURN', () => {
        if (!socket.userId) return;

        if (turnManager.currentPlayer() === socket.userId) {
            turnManager.endTurn();
        }
    });

    socket.on('CHAT_MESSAGE', async (data) => {
        if (!socket.userId) return;

        const { message } = data;

        if (message.length > 500) {
            socket.emit('ERROR', { message: 'Wiadomość za długa (max 500 znaków)' });
            return;
        }

        try {
            await pgPool.query(
                'INSERT INTO global_chat (player_id, message) VALUES ($1, $2)',
                [socket.userId, message]
            );

            io.emit('CHAT_MESSAGE', {
                playerId: socket.userId,
                username: socket.user.username,
                message,
                timestamp: new Date().toISOString()
            });
        } catch (error) {
            socket.emit('ERROR', { message: 'Błąd wysyłania wiadomości' });
        }
    });

    socket.on('disconnect', () => {
        console.log('Rozłączenie:', socket.id);

        if (socket.userId) {
            turnManager.removePlayer(socket.userId);

            io.emit('PLAYER_LEFT', {
                playerId: socket.userId,
                username: socket.user ? socket.user.username : 'Unknown'
            });
        }
    });
});

// ============================================
// FUNKCJE POMOCNICZE
// ============================================

function getBuildingCost(buildingId) {
    const costs = {
        'village_hall': { gold: 0 },
        'town_hall': { gold: 2500, wood: 5 },
        'city_hall': { gold: 5000, wood: 5, ore: 5, crystal: 5, gems: 5 },
        'capitol': { gold: 10000, wood: 10, ore: 10 },
        'fort': { gold: 5000, wood: 20, ore: 20 },
        'citadel': { gold: 2500, wood: 5, ore: 5 },
        'castle': { gold: 5000, wood: 10, ore: 10 },
        'guardhouse': { gold: 500 },
        'archers_tower': { gold: 1000 },
        'griffin_tower': { gold: 1000 },
        'barracks': { gold: 1000 },
        'monastery': { gold: 1000 },
        'training_grounds': { gold: 2000 },
        'portal_of_glory': { gold: 5000 }
    };
    return costs[buildingId] || { gold: 0 };
}

function getUnitData(unitType) {
    const units = {
        'Pikeman': { cost: { gold: 60 } },
        'Archer': { cost: { gold: 100 } },
        'Griffin': { cost: { gold: 200 } },
        'Swordsman': { cost: { gold: 300 } },
        'Monk': { cost: { gold: 400 } },
        'Cavalier': { cost: { gold: 1000 } },
        'Angel': { cost: { gold: 3000, crystal: 1 } }
    };
    return units[unitType] || { cost: { gold: 100 } };
}

function hasEnoughResources(resources, cost) {
    for (const [resource, amount] of Object.entries(cost)) {
        if ((resources[resource] || 0) < amount) {
            return false;
        }
    }
    return true;
}

function subtractResources(resources, cost) {
    const newResources = { ...resources };
    for (const [resource, amount] of Object.entries(cost)) {
        newResources[resource] = (newResources[resource] || 0) - amount;
    }
    return newResources;
}

function multiplyResources(resources, multiplier) {
    const result = {};
    for (const [resource, amount] of Object.entries(resources)) {
        result[resource] = amount * multiplier;
    }
    return result;
}

function getSocketByPlayerId(playerId) {
    const sockets = io.sockets.sockets;
    for (const [id, socket] of sockets) {
        if (socket.userId === playerId) {
            return socket;
        }
    }
    return null;
}

// ============================================
// START SERWERA
// ============================================

server.listen(CONFIG.PORT, () => {
    console.log('🏰 Heroes of Might and Magic III - Złota Edycja ONLINE');
    console.log('⚔️  Serwer uruchomiony na porcie ' + CONFIG.PORT);
    console.log('👥 Max graczy: ' + CONFIG.MAX_PLAYERS);
    console.log('⏱️  Czas tury: ' + CONFIG.TURN_DURATION / 60 + ' minut');
    console.log('🗺️  Rozmiar mapy: ' + CONFIG.MAP_SIZE + 'x' + CONFIG.MAP_SIZE);
});

module.exports = { app, server, io, turnManager, combatManager, mapManager };