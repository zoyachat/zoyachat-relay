/**
 * Group handler — create, invite, remove, permissions, dissolve.
 */
const { v4: uuidv4 } = require('uuid')
const db = require('./db')

function createGroup(userId, opts, pushToUser) {
  const { name, description, avatarColor, memberUserIds, maxMembers } = opts
  if (!name) return { ok: false, error: 'MISSING_FIELDS' }

  const groupId = uuidv4()
  const creator = db.getUserById(userId)
  db.createGroup(groupId, name, description || '', avatarColor || '#8b5cf6', userId, Math.min(maxMembers || 20, 100))
  db.addGroupMember(groupId, userId, creator?.display_name || '', 'creator')

  // Invite initial members
  const invited = []
  if (Array.isArray(memberUserIds)) {
    for (const mid of memberUserIds.slice(0, (maxMembers || 20) - 1)) {
      const user = db.getUserById(mid)
      if (!user) continue
      db.addGroupMember(groupId, mid, user.display_name || '', 'member')
      invited.push(mid)
      // Notify invited user
      pushToUser(mid, {
        type: 'group_invite',
        groupId,
        groupName: name,
        from: userId,
        fromName: creator?.display_name || '',
      })
    }
  }

  try { db.insertAnalytics('group_create', userId) } catch {}
  return { ok: true, groupId, invited }
}

function inviteMembers(groupId, userId, targetUserIds, pushToUser) {
  const group = db.getGroup(groupId)
  if (!group) return { ok: false, error: 'GROUP_NOT_FOUND' }

  const member = db.getGroupMember(groupId, userId)
  if (!member || (member.role !== 'creator' && member.role !== 'admin')) {
    return { ok: false, error: 'NOT_ADMIN' }
  }

  const members = db.getGroupMembers(groupId)
  let added = 0
  const inviter = db.getUserById(userId)

  for (const tid of targetUserIds) {
    if (members.length + added >= group.max_members) break
    const existing = db.getGroupMember(groupId, tid)
    if (existing) continue
    const user = db.getUserById(tid)
    if (!user) continue

    db.addGroupMember(groupId, tid, user.display_name || '', 'member')
    added++

    pushToUser(tid, {
      type: 'group_invite',
      groupId,
      groupName: group.name,
      from: userId,
      fromName: inviter?.display_name || '',
    })
  }

  // Notify existing members about new members
  const updatedMembers = db.getGroupMembers(groupId)
  for (const m of members) {
    pushToUser(m.user_id, { type: 'group_members_changed', groupId, members: updatedMembers.map(simplifyMember) })
  }

  return { ok: true, added }
}

function removeMember(groupId, adminUserId, targetUserId, pushToUser) {
  const group = db.getGroup(groupId)
  if (!group) return { ok: false, error: 'GROUP_NOT_FOUND' }

  const admin = db.getGroupMember(groupId, adminUserId)
  if (!admin || (admin.role !== 'creator' && admin.role !== 'admin')) {
    return { ok: false, error: 'NOT_ADMIN' }
  }

  const target = db.getGroupMember(groupId, targetUserId)
  if (!target) return { ok: false, error: 'NOT_MEMBER' }
  if (target.role === 'creator') return { ok: false, error: 'CANNOT_REMOVE_CREATOR' }

  db.removeGroupMember(groupId, targetUserId)
  pushToUser(targetUserId, { type: 'group_removed', groupId, groupName: group.name })

  // Notify remaining members
  const members = db.getGroupMembers(groupId)
  for (const m of members) {
    pushToUser(m.user_id, { type: 'group_members_changed', groupId, members: members.map(simplifyMember) })
  }

  return { ok: true }
}

function leaveGroup(groupId, userId, pushToUser) {
  const member = db.getGroupMember(groupId, userId)
  if (!member) return { ok: false, error: 'NOT_MEMBER' }
  if (member.role === 'creator') return { ok: false, error: 'CREATOR_CANNOT_LEAVE' }

  db.removeGroupMember(groupId, userId)

  const members = db.getGroupMembers(groupId)
  for (const m of members) {
    pushToUser(m.user_id, { type: 'group_members_changed', groupId, members: members.map(simplifyMember) })
  }

  return { ok: true }
}

function dissolveGroup(groupId, userId, pushToUser) {
  const group = db.getGroup(groupId)
  if (!group) return { ok: false, error: 'GROUP_NOT_FOUND' }
  if (group.creator_id !== userId) return { ok: false, error: 'NOT_CREATOR' }

  const members = db.getGroupMembers(groupId)
  db.deleteGroup(groupId)

  for (const m of members) {
    pushToUser(m.user_id, { type: 'group_dissolved', groupId, groupName: group.name })
  }

  return { ok: true }
}

function getGroupInfo(groupId, userId) {
  const group = db.getGroup(groupId)
  if (!group) return null
  const members = db.getGroupMembers(groupId)
  const myMember = members.find(m => m.user_id === userId)
  return {
    ...group,
    members: members.map(simplifyMember),
    myRole: myMember?.role || null,
    memberCount: members.length,
  }
}

function updateGroupInfo(groupId, userId, fields) {
  const member = db.getGroupMember(groupId, userId)
  if (!member || (member.role !== 'creator' && member.role !== 'admin')) {
    return { ok: false, error: 'NOT_ADMIN' }
  }
  db.updateGroup(groupId, fields)
  return { ok: true }
}

function simplifyMember(m) {
  return { userId: m.user_id, displayName: m.display_name, role: m.role, isMuted: !!m.is_muted }
}

module.exports = { createGroup, inviteMembers, removeMember, leaveGroup, dissolveGroup, getGroupInfo, updateGroupInfo }
