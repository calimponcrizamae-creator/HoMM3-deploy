const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(express.static('public'));
app.use(express.json());

// In-memory storage
const players = new Map();
const chat = [];
let onlineCount = 0;

// WebSocket handlers
io.on('connection', (socket) => {
    console.log('New connection:', socket.id);

    socket.on('AUTHENTICATE', (data) => {
        const player = { 
            id: socket.id, 
            username: data.username || 'Gracz_' + Math.floor(Math.random() * 9999), 
            faction: data.faction || 'CASTLE'
        };
        players.set(socket.id, player);
        onlineCount++;
        
        socket.emit('AUTHENTICATED', { 
            success: true, 
            user: player,
            heroes: [{
                id: 'hero1', 
                name: 'Bohater_' + player.username, 
                faction: player.faction,
                level: 1, 
                attack: 2, 
                defense: 2, 
                spell_power: 1, 
                knowledge: 1,
                mana: 10, 
                max_mana: 10, 
                movement_points: 2000,
                position_x: 0,
                position_y: 0,
                army: [{type: 'Pikeman', count: 50}, {type: 'Archer', count: 20}],
                spells: ['Magic_Arrow', 'Haste']
            }],
            castles: [{
                id: 'castle1', 
                name: 'Zamek_' + player.username, 
                faction: player.faction,
                position_x: 100,
                position_y: 100,
                buildings: ['village_hall', 'fort', 'tavern'],
                garrison: [{type: 'Pikeman', count: 30}, {type: 'Archer', count: 15}],
                income: 500
            }]
        });
        
        io.emit('PLAYER_JOINED', { 
            username: player.username,
            onlinePlayers: onlineCount,
            message: player.username + ' dołączył do gry'
        });
        
        console.log(player.username + ' authenticated. Online:', onlineCount);
    });
    
    socket.on('CHAT_MESSAGE', (data) => {
        const player = players.get(socket.id);
        if (!player) return;
        
        const msg = { 
            username: player.username, 
            message: data.message || '', 
            timestamp: new Date().toISOString()
        };
        chat.push(msg);
        if (chat.length > 100) chat.shift();
        io.emit('CHAT_MESSAGE', msg);
    });
    
    socket.on('MOVE_HERO', (data) => {
        const player = players.get(socket.id);
        if (!player) return;
        
        io.emit('HERO_MOVED', {
            playerId: socket.id,
            username: player.username,
            heroId: data.heroId,
            x: data.x,
            y: data.y
        });
    });
    
    socket.on('END_TURN', () => {
        const player = players.get(socket.id);
        if (!player) return;
        
        io.emit('TURN_ENDED', {
            playerId: socket.id,
            username: player.username
        });
    });
    
    socket.on('disconnect', () => {
        const player = players.get(socket.id);
        if (player) {
            players.delete(socket.id);
            onlineCount = Math.max(0, onlineCount - 1);
            io.emit('PLAYER_LEFT', { 
                username: player.username,
                onlinePlayers: onlineCount,
                message: player.username + ' opuścił grę'
            });
            console.log(player.username + ' disconnected. Online:', onlineCount);
        }
    });
});

// REST API endpoints
app.get('/', (req, res) => {
    res.json({ message: 'HoMM3-deploy backend is running' });
});

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        onlinePlayers: onlineCount, 
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

app.get('/api/players', (req, res) => {
    const playerList = Array.from(players.values()).map(p => ({
        id: p.id,
        username: p.username,
        faction: p.faction
    }));
    res.json({ players: playerList, count: playerList.length });
});

app.get('/api/chat', (req, res) => {
    res.json({ messages: chat, count: chat.length });
});

app.get('/api/ranking', (req, res) => {
    res.json({ 
        players: Array.from(players.values()),
        totalOnline: onlineCount
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log('🏰 HoMM3 Online Server');
    console.log('⚔️  Started on port', PORT);
    console.log('📍 http://localhost:' + PORT);
});

module.exports = { app, server, io };
