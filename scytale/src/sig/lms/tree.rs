//! The Merkle tree (RFC 8554 section 5) and its traversal.
//!
//! Key generation hashes every leaf once to find the root. Signing
//! needs, for each leaf in turn, the sibling of every node on its path
//! to the root, and recomputing those from the seed would cost the
//! whole tree each time. The BDS algorithm (Buchmann, Dahmen and
//! Schneider, "Merkle tree traversal revisited", 2008) keeps instead
//! a fixed amount of state, initialised during the key generation
//! walk, and spends about `h/2` leaf computations a signature keeping
//! it one step ahead: the next authentication path is always ready
//! when its leaf comes up. This is a port of the `xmss_core_fast`
//! reference code's version of it, with `k = 0` so that there are no
//! retained top nodes, every level having a treehash instance.
//!
//! One instance per level builds the right node the path will need
//! next at that level, a leaf at a time, on a stack shared by every
//! instance; the scheduler gives each update to the instance whose
//! lowest stacked node is lowest, which keeps each instance's nodes
//! at the top while it works. The scheduler's proof wants `h` even;
//! for the odd heights here the budget is rounded up, and
//! [`advance`](Bds::advance) checks that each node it needs is
//! finished, computing it from the seed outright if ever it is not,
//! so a scheduling shortfall could only cost time.

use zeroize::Zeroize;

use super::{H_MAX, Hasher, I_SIZE, Lmots, Lms, N_MAX, Node, ots};

/// Ends the hash of a leaf.
const D_LEAF: [u8; 2] = [0x82, 0x82];
/// Ends the hash of an interior node.
const D_INTR: [u8; 2] = [0x83, 0x83];

/// A node of the stack that key generation and the treehash
/// instances build on: deep enough for a walk of the whole tree.
const STACK: usize = H_MAX + 1;

/// The leaf hash `H(I || u32str(node_num) || D_LEAF || K)`.
pub(super) fn leaf_hash(
    hasher: &mut Hasher,
    i: &[u8; I_SIZE],
    node_num: u32,
    k: &[u8],
) -> Node {
    hasher.digest(&[i, &node_num.to_be_bytes(), &D_LEAF, k])
}

/// The interior node hash `H(I || u32str(node_num) || D_INTR || left
/// || right)`.
pub(super) fn node_hash(
    hasher: &mut Hasher,
    i: &[u8; I_SIZE],
    node_num: u32,
    left: &[u8],
    right: &[u8],
) -> Node {
    hasher.digest(&[i, &node_num.to_be_bytes(), &D_INTR, left, right])
}

/// One tree's parameters and secrets, with a hash ready: what
/// computing any node takes.
pub(super) struct Tree<'a> {
    lms: Lms,
    ots: Lmots,
    i: &'a [u8; I_SIZE],
    seed: &'a Node,
    hasher: Hasher,
}

impl<'a> Tree<'a> {
    pub(super) fn new(
        lms: Lms,
        ots: Lmots,
        i: &'a [u8; I_SIZE],
        seed: &'a Node,
    ) -> Self {
        Tree {
            lms,
            ots,
            i,
            seed,
            hasher: Hasher::new(lms.family()),
        }
    }

    fn h(&self) -> u32 {
        self.lms.h()
    }

    fn n(&self) -> usize {
        self.lms.m()
    }

    /// Leaf `q`: the hash of its one-time public key.
    fn leaf(&mut self, q: u32) -> Node {
        let k = ots::Ots::new(self.ots, &mut self.hasher, self.i, q)
            .public_key(self.seed);
        let (node_num, n) = ((1u32 << self.h()) + q, self.n());
        leaf_hash(&mut self.hasher, self.i, node_num, &k[..n])
    }

    /// The parent of `left` and `right`, at height `level` (the
    /// leaves being 0) and `index` along that level.
    fn parent(
        &mut self,
        level: u32,
        index: u32,
        left: &Node,
        right: &Node,
    ) -> Node {
        let n = self.n();
        let node_num = (1u32 << (self.h() - level)) + index;
        node_hash(&mut self.hasher, self.i, node_num, &left[..n], &right[..n])
    }

    /// The node at `level` and `index`, from the seed, with a stack
    /// of its own: `2^level` leaves of work.
    pub(super) fn compute(&mut self, level: u32, index: u32) -> Node {
        let mut stack = [[0u8; N_MAX]; STACK];
        let mut levels = [0u32; STACK];
        let mut top = 0;
        let first = index << level;
        for q in first..first + (1 << level) {
            stack[top] = self.leaf(q);
            levels[top] = 0;
            top += 1;
            while top > 1 && levels[top - 1] == levels[top - 2] {
                let l = levels[top - 1];
                let parent_index = q >> (l + 1);
                stack[top - 2] = self.parent(
                    l + 1,
                    parent_index,
                    &stack[top - 2],
                    &stack[top - 1],
                );
                levels[top - 2] = l + 1;
                top -= 1;
            }
        }
        stack[0]
    }
}

/// A treehash instance: builds one node of its level, a leaf a time.
#[derive(Clone, Copy, Zeroize)]
struct Treehash {
    /// The node when `done`.
    node: Node,
    /// The next leaf to add.
    next: u32,
    /// How many nodes of the shared stack are this instance's, at
    /// the top of it while it works.
    used: u8,
    done: bool,
}

const IDLE: Treehash = Treehash {
    node: [0u8; N_MAX],
    next: 0,
    used: 0,
    done: true,
};

/// The traversal state of one tree.
#[derive(Clone, Zeroize)]
pub(super) struct Bds {
    /// The authentication path of the current leaf: `auth[j]` is the
    /// sibling of its ancestor at height `j`.
    auth: [Node; H_MAX],
    /// Left nodes kept for the next time their level's path node
    /// changes.
    keep: [Node; H_MAX / 2],
    /// One instance per level below the root.
    treehash: [Treehash; H_MAX],
    stack: [Node; STACK],
    levels: [u8; STACK],
    top: u8,
    /// How often [`advance`](Self::advance) found a node unfinished
    /// and computed it outright; a count the tests check stays zero.
    #[cfg(test)]
    pub(super) slow: u32,
}

impl Bds {
    /// A state with nothing in it, for [`init`](Self::init) or a
    /// decoder to fill.
    pub(super) fn blank() -> Self {
        Bds {
            auth: [[0u8; N_MAX]; H_MAX],
            keep: [[0u8; N_MAX]; H_MAX / 2],
            treehash: [IDLE; H_MAX],
            stack: [[0u8; N_MAX]; STACK],
            levels: [0u8; STACK],
            top: 0,
            #[cfg(test)]
            slow: 0,
        }
    }

    /// The authentication path of the current leaf.
    pub(super) fn auth(&self, h: usize) -> &[Node] {
        &self.auth[..h]
    }

    /// Walks the whole tree and returns its root, leaving the state
    /// ready for leaf 0: the path of leaf 0, and each level's
    /// instance holding the node leaf 0's path will need next.
    pub(super) fn init(&mut self, tree: &mut Tree) -> Node {
        let h = tree.h();
        for instance in &mut self.treehash[..h as usize] {
            *instance = IDLE;
        }
        let mut top = 0usize;
        let mut levels = [0u32; STACK];
        for q in 0..(1u32 << h) {
            self.stack[top] = tree.leaf(q);
            levels[top] = 0;
            top += 1;
            while top > 1 && levels[top - 1] == levels[top - 2] {
                let l = levels[top - 1];
                // The node on top is the one at `l` with index q >> l.
                match q >> l {
                    1 => self.auth[l as usize] = self.stack[top - 1],
                    3 => self.treehash[l as usize].node = self.stack[top - 1],
                    _ => {}
                }
                self.stack[top - 2] = tree.parent(
                    l + 1,
                    q >> (l + 1),
                    &self.stack[top - 2],
                    &self.stack[top - 1],
                );
                levels[top - 2] = l + 1;
                top -= 1;
            }
        }
        let root = self.stack[0];
        self.stack[0] = [0u8; N_MAX];
        root
    }

    /// Moves from leaf `q`, just used, to leaf `q + 1`, which must
    /// exist: makes its path current and gives the instances this
    /// signature's share of work.
    pub(super) fn advance(&mut self, tree: &mut Tree, q: u32) {
        let h = tree.h();
        debug_assert!(q + 1 < (1 << h));
        // The lowest zero bit of q: the height at which q + 1's path
        // leaves q's.
        let tau = q.trailing_ones();
        let mut buf_right = [0u8; N_MAX];
        if tau > 0 {
            // The old path node at tau - 1 and the left node kept for
            // it make the new node at tau; read before `keep` moves.
            buf_right = self.keep[((tau - 1) >> 1) as usize];
        }
        if (q >> (tau + 1)) & 1 == 0 && tau < h - 1 {
            self.keep[(tau >> 1) as usize] = self.auth[tau as usize];
        }
        if tau == 0 {
            // q is a left leaf; q + 1's sibling is q itself.
            self.auth[0] = tree.leaf(q);
        } else {
            let left = self.auth[(tau - 1) as usize];
            self.auth[tau as usize] =
                tree.parent(tau, q >> tau, &left, &buf_right);
            for level in 0..tau {
                let instance = &self.treehash[level as usize];
                self.auth[level as usize] = if instance.done {
                    instance.node
                } else {
                    #[cfg(test)]
                    {
                        self.slow += 1;
                    }
                    tree.compute(level, ((q + 1) >> level) ^ 1)
                };
            }
            for level in 0..tau {
                let start = (q + 1) + (3 << level);
                if u64::from(start) < tree.lms.leaves() {
                    self.treehash[level as usize] = Treehash {
                        node: [0u8; N_MAX],
                        next: start,
                        used: 0,
                        done: false,
                    };
                }
            }
        }
        let budget = h.div_ceil(2);
        for _ in 0..budget {
            if !self.update_one(tree) {
                break;
            }
        }
    }

    /// The lowest level among `instance`'s nodes on the stack.
    fn min_level(&self, instance: &Treehash, h: u32) -> u32 {
        let mut r = h;
        for i in 0..instance.used as usize {
            let level = u32::from(self.levels[self.top as usize - i - 1]);
            r = r.min(level);
        }
        r
    }

    /// One leaf of work for the instance that needs it most; `false`
    /// when every instance is done.
    fn update_one(&mut self, tree: &mut Tree) -> bool {
        let h = tree.h();
        let mut chosen = None;
        let mut l_min = h;
        for level in 0..h {
            let instance = &self.treehash[level as usize];
            let low = if instance.done {
                h
            } else if instance.used == 0 {
                level
            } else {
                self.min_level(instance, h)
            };
            if low < l_min {
                chosen = Some(level);
                l_min = low;
            }
        }
        let Some(level) = chosen else {
            return false;
        };
        self.treehash_update(tree, level);
        true
    }

    /// One leaf of work for the instance at `level`.
    fn treehash_update(&mut self, tree: &mut Tree, level: u32) {
        let instance = &self.treehash[level as usize];
        let next = instance.next;
        let mut used = instance.used;
        let mut node = tree.leaf(next);
        let mut height = 0u32;
        while used > 0
            && u32::from(self.levels[self.top as usize - 1]) == height
        {
            let left = self.stack[self.top as usize - 1];
            node = tree.parent(height + 1, next >> (height + 1), &left, &node);
            height += 1;
            used -= 1;
            self.top -= 1;
        }
        let instance = &mut self.treehash[level as usize];
        if height == level {
            instance.node = node;
            instance.done = true;
            instance.used = used;
        } else {
            self.stack[self.top as usize] = node;
            self.levels[self.top as usize] = height as u8;
            self.top += 1;
            instance.used = used + 1;
            instance.next = next + 1;
        }
    }

    /// The length of [`write`](Self::write) for a tree of height `h`
    /// and node length `n`.
    pub(super) const fn encoded_len(h: usize, n: usize) -> usize {
        // auth, keep, treehash (node, next, used, done), top, then
        // the stack's level and node per entry.
        h * n + (h / 2) * n + h * (n + 6) + 1 + (h + 1) * (n + 1)
    }

    /// Writes the state for a tree of height `h` and node length `n`
    /// through `put`, as [`read`](Self::read) reads it.
    pub(super) fn write(
        &self,
        h: usize,
        n: usize,
        put: &mut impl FnMut(&[u8]),
    ) {
        for node in &self.auth[..h] {
            put(&node[..n]);
        }
        for node in &self.keep[..h / 2] {
            put(&node[..n]);
        }
        for instance in &self.treehash[..h] {
            put(&instance.node[..n]);
            put(&instance.next.to_be_bytes());
            put(&[instance.used, u8::from(instance.done)]);
        }
        put(&[self.top]);
        for i in 0..=h {
            put(&[self.levels[i]]);
            put(&self.stack[i][..n]);
        }
    }

    /// A state from `bytes`, exactly [`encoded_len`](Self::encoded_len)
    /// of them; `None` for a length or a field outside the tree.
    pub(super) fn read(h: usize, n: usize, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::encoded_len(h, n) {
            return None;
        }
        let mut state = Self::blank();
        let mut at = 0usize;
        let mut take = |len: usize| {
            let piece = &bytes[at..at + len];
            at += len;
            piece
        };
        for node in &mut state.auth[..h] {
            node[..n].copy_from_slice(take(n));
        }
        for node in &mut state.keep[..h / 2] {
            node[..n].copy_from_slice(take(n));
        }
        for instance in &mut state.treehash[..h] {
            instance.node[..n].copy_from_slice(take(n));
            instance.next = super::u32_at(take(4), 0);
            let flags = take(2);
            instance.used = flags[0];
            instance.done = match flags[1] {
                0 => false,
                1 => true,
                _ => return None,
            };
            if u64::from(instance.next) > (1u64 << h)
                || instance.used as usize > h + 1
            {
                return None;
            }
        }
        state.top = take(1)[0];
        if state.top as usize > h + 1 {
            return None;
        }
        for i in 0..=h {
            let level = take(1)[0];
            if level as usize > h {
                return None;
            }
            state.levels[i] = level;
            state.stack[i][..n].copy_from_slice(take(n));
        }
        Some(state)
    }
}
