import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { useAuth } from '../contexts/AuthContext';
import API_URL from '../config';

const BookingEdit = () => {
    const { id } = useParams();
    const navigate = useNavigate();
    const { token } = useAuth();

    const [loading, setLoading] = useState(true);
    const [formData, setFormData] = useState({
        fullname: '',
        email: '',
        phone: '',
        checkin: '',
        checkout: '',
        roomtype: '',
        guests: 1,
        comment: '',
    });

    const maxGuests = { standard: 2, deluxe: 3, suite: 4 };

    // ✅ ดึงข้อมูล booking
    const fetchBooking = async () => {
        try {
            const response = await axios.get(`${API_URL}/api/bookings/${id}`);
            setFormData(response.data);
            setLoading(false);
        } catch (err) {
            console.error(err);
            setLoading(false);
        }
    };

    // ✅ FIX สำคัญ: ต้องมี useEffect
    useEffect(() => {
        const loadData = async () => {
            await fetchBooking();
        };

        loadData();
    }, [id]);

    // ✅ handle input
    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: value
        }));
    };

    // ✅ submit form
    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            await axios.put(`${API_URL}/api/bookings/${id}`, formData, {
                headers: { Authorization: `Bearer ${token}` },
            });

            alert('แก้ไขข้อมูลสำเร็จ');
            navigate('/admin/bookings');
        } catch (err) {
            alert(err.response?.data?.error || 'เกิดข้อผิดพลาด');
        }
    };

    // ✅ loading
    if (loading) {
        return <div className="text-center py-4">กำลังโหลด...</div>;
    }

    return (
        <div className="max-w-md mx-auto mt-10 p-6 bg-white rounded-lg shadow-md">
            <h2 className="text-2xl font-bold mb-6 text-center">แก้ไขข้อมูลการจอง</h2>

            <form onSubmit={handleSubmit} className="space-y-4">

                {/* ---- ข้อมูลผู้จอง ---- */}
                {[
                    { label: 'ชื่อ-นามสกุล:', name: 'fullname', type: 'text' },
                    { label: 'อีเมล:', name: 'email', type: 'email' },
                    { label: 'เบอร์โทรศัพท์:', name: 'phone', type: 'tel' },
                ].map(({ label, name, type }) => (
                    <div key={name}>
                        <label className="block text-gray-700 mb-2">{label}</label>
                        <input
                            type={type}
                            name={name}
                            value={formData[name]}
                            onChange={handleChange}
                            className="w-full p-2 border rounded-md focus:ring-2 focus:ring-blue-500"
                            required
                        />
                    </div>
                ))}

                {/* ---- วันที่ ---- */}
                <div>
                    <label className="block text-gray-700 mb-2">วันที่เช็คอิน:</label>
                    <input
                        type="date"
                        name="checkin"
                        value={formData.checkin}
                        onChange={handleChange}
                        className="w-full p-2 border rounded-md focus:ring-2 focus:ring-blue-500"
                        required
                    />
                </div>

                <div>
                    <label className="block text-gray-700 mb-2">วันที่เช็คเอาท์:</label>
                    <input
                        type="date"
                        name="checkout"
                        value={formData.checkout}
                        onChange={handleChange}
                        min={formData.checkin}
                        className="w-full p-2 border rounded-md focus:ring-2 focus:ring-blue-500"
                        required
                    />
                </div>

                {/* ---- ประเภทห้อง ---- */}
                <div>
                    <label className="block text-gray-700 mb-2">ประเภทห้องพัก:</label>
                    <select
                        name="roomtype"
                        value={formData.roomtype}
                        onChange={handleChange}
                        className="w-full p-2 border rounded-md focus:ring-2 focus:ring-blue-500"
                        required
                    >
                        <option value="standard">ห้องมาตรฐาน (สูงสุด 2 ท่าน)</option>
                        <option value="deluxe">ห้องดีลักซ์ (สูงสุด 3 ท่าน)</option>
                        <option value="suite">ห้องสวีท (สูงสุด 4 ท่าน)</option>
                    </select>
                </div>

                {/* ---- จำนวนผู้เข้าพัก ---- */}
                <div>
                    <label className="block text-gray-700 mb-2">จำนวนผู้เข้าพัก:</label>
                    <input
                        type="number"
                        name="guests"
                        value={formData.guests}
                        onChange={handleChange}
                        min="1"
                        max={formData.roomtype ? maxGuests[formData.roomtype] : 4}
                        className="w-full p-2 border rounded-md focus:ring-2 focus:ring-blue-500"
                        required
                    />
                </div>

                {/* ---- หมายเหตุ ---- */}
                <div>
                    <label className="block text-gray-700 mb-2">หมายเหตุ:</label>
                    <input
                        type="text"
                        name="comment"
                        value={formData.comment || ''}
                        onChange={handleChange}
                        className="w-full p-2 border rounded-md focus:ring-2 focus:ring-blue-500"
                    />
                </div>

                <div className="flex space-x-4">
                    <button
                        type="submit"
                        className="flex-1 bg-blue-500 text-white py-2 px-4 rounded-md hover:bg-blue-600"
                    >
                        บันทึก
                    </button>

                    <button
                        type="button"
                        onClick={() => navigate('/admin/bookings')}
                        className="flex-1 bg-gray-500 text-white py-2 px-4 rounded-md hover:bg-gray-600"
                    >
                        ยกเลิก
                    </button>
                </div>

            </form>
        </div>
    );
};

export default BookingEdit;