const express = require('express')
const User = require('../models/User')
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path')
const fs = require('fs');

const router = express.Router()

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');  // Directory where images will be stored
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);  // Rename file to avoid duplicates
  }
});

const upload = multer({ storage: storage });

const secretKey = 'ecda1cd47fd1c30ae4cb4fd56042ffac4ba5708acd7f80a20b76bce843e6d8a7';

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    console.error('Access denied: No token provided');
    return res.status(401).json({ message: 'Access denied' });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      console.error('Invalid token:', err);
      return res.status(403).json({ message: 'Invalid token' });
    }
    console.log('Authenticated user:', user);
    req.user = user;
    next();
  });
}

// POST /api/posts - Create a new post with image
router.post('/', authenticateToken, upload.single('image'), async (req, res) => {
  const { content } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

  try {
    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const newPost = {
      content,
      imageUrl,
      postedBy: req.user.userId,
      username: user.username
    };

    user.posts.push(newPost);
    await user.save();

    res.status(201).json({ post: newPost });
  } catch (err) {
    console.error('Error creating post:', err);
    res.status(500).json({ message: 'Server Error' });
  }
});



// POST /api/posts/:postId/comments - Add a comment to a post
router.post('/:postId/comments', authenticateToken, async (req, res) => {
    const { postId } = req.params;
    const { text } = req.body;
    try {
      const user = await User.findById(req.user.userId);
      const post = user.posts.id(postId);
      if (!post) {
        return res.status(404).json({ message: 'Post not found' });
      }
      post.comments.push({ text, postedBy: req.user.userId });
      await user.save();
      res.status(201).json({ message: 'Comment added successfully' });
    } catch (err) {
      console.error(err.message);
      res.status(500).json({ message: 'Server Error' });
    }
  });

// GET /api/posts/:postId/comments - Get comments for a specific post
router.get('/:postId/comments', async (req, res) => {
  const { postId } = req.params;

  try {
    const user = await User.findOne({ 'posts._id': postId }); // Find user with posts containing postId
    if (!user) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const post = user.posts.find(post => post._id.equals(postId)); // Find the specific post
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const comments = post.comments; // Get comments array from the post
    res.status(200).json(comments);
  } catch (error) {
    console.error('Error fetching comments:', error);
    res.status(500).json({ message: 'Server Error' });
  }
});

// PUT /api/posts/:postId/like - Like a post
router.put('/:postId/like', authenticateToken, async (req, res) => {
  const { postId } = req.params;
  try {
    const user = await User.findById(req.user.userId);
    const post = user.posts.id(postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    if (!post.likes.includes(req.user.userId)) {
      post.likes.push(req.user.userId); // Add like
    } else {
      post.likes = post.likes.filter(userId => userId !== req.user.userId); // Remove like
    }

    await user.save();
    res.json({ message: 'Post liked/unliked successfully' });
  } catch (err) {
    console.error('Error liking/unliking post:', err);
    res.status(500).json({ message: 'Server Error' });
  }
});


  // Example route in your backend (Node.js/Express)
// GET /api/posts/liked
router.get('/liked', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).populate('posts');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    const likedPosts = user.posts.filter(post => post.likes.includes(req.user.userId));
    res.json(likedPosts);
  } catch (error) {
    console.error('Error fetching liked posts:', error);
    res.status(500).json({ message: 'Server Error' });
  }
});


// Get all posts
router.get('/', authenticateToken, async (req, res) => {
    try {
      const user = await User.findById(req.user.userId).populate('posts.postedBy', 'email'); // Populate postedBy with user's email
      if (!user) {
        console.error('User not found:', req.user.userId);
        return res.status(404).json({ message: 'User not found' });
      }
      console.log('User posts:', user.posts);
      res.json(user.posts);
    } catch (err) {
      console.error('Error fetching posts:', err);
      res.status(500).send({ message: err.message });
    }
  });

// Get a specific post by ID
router.get('/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
      const user = await User.findById(req.user.userId);
      const post = user.posts.id(id);
      if (!post) {
        return res.status(404).json({ message: 'Post not found' });
      }
      res.json(post);
    } catch (err) {
      console.log(err.message);
      res.status(500).send({ message: err.message });
    }
  });

//Updating || modifyning posts by ID
router.put('/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { title, content } = req.body;
    try {
      const user = await User.findById(req.user.userId);
      const post = user.posts.id(id);
      if (!post) {
        return res.status(404).json({ message: 'Post not found' });
      }
      post.title = title !== undefined ? title : post.title;
      post.content = content !== undefined ? content : post.content;
      await user.save();
      res.json({ message: 'Post updated successfully' });
    } catch(err){
        console.log(err.message);
        res.status(500).send({message:err.message})
    }
})

// DELETE /api/posts/:id - Delete a post
router.delete('/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
      const user = await User.findById(req.user.userId);
      const post = user.posts.id(id);
      if (!post) {
        return res.status(404).json({ message: 'Post not found' });
      }
      post.remove();
      await user.save();
      res.json({ message: 'Post deleted successfully' });
    } catch (err) {
      console.error(err.message);
      res.status(500).json({ message: 'Server Error' });
    }
  });



module.exports =  router;
